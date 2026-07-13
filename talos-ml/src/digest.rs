//! RFC 0011 P2d — the disagreement-digest delivery (human-in-the-loop).
//!
//! The mechanism that lets a model actually EARN its way out of shadow:
//! the lifecycle policy gates advancement on human corrections
//! (`min_corrections_per_class`) and per-class recall, but those
//! corrections only happen if a human sees the cases worth correcting.
//! This scheduled task delivers them.
//!
//! Every `ML_DIGEST_INTERVAL_SECS` (default 6 h) it scans policy-bearing
//! models, and for each that (a) has a `config_json.digest.actor_id`
//! configured and (b) has pending disagreements, it decrypts the
//! pending fast-vs-LLM divergences + low-confidence samples (owner-
//! scoped) and writes a compact digest to THAT actor's `actor_memory`
//! (which is itself encrypted at rest) under `ml_digest/<model>`. The
//! user reviews it like their daily brief and resolves each entry with
//! `ml_resolve_disagreement(id, correct_label)` — appending a gold
//! correction that counts toward the policy.
//!
//! Delivery is OPT-IN (no digest actor → the task logs the pending
//! count and moves on; the disagreements stay reviewable via the
//! `ml_disagreements` MCP surface). The digest value carries the
//! disagreement `id` for each entry so resolution is one call per item.

use anyhow::{Context, Result};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::lifecycle::LifecycleService;

const DEFAULT_DIGEST_INTERVAL_SECS: u64 = 21_600; // 6 h
/// Per-tick model scan cap — backlog catches up over ticks.
const MODELS_PER_TICK: i64 = 50;
/// Entries per digest — bounded so the memory value stays small; the
/// full set remains reviewable via `ml_disagreements`.
const DIGEST_ENTRIES: i64 = 20;
/// Feature preview length in the digest (the full text stays encrypted
/// in ml_disagreements; the digest carries a short reviewable excerpt).
const PREVIEW_CHARS: usize = 160;
/// Digest memory TTL FLOOR — refreshed every tick, so a couple of days
/// keeps it present between reviews without lingering forever. The
/// EFFECTIVE ttl is `max(floor, 2× interval)` so raising the interval
/// above 48 h can't let the entry lapse between refreshes (see
/// [`effective_ttl_hours`]).
const DIGEST_TTL_HOURS: f64 = 48.0;

/// Parsed `ML_DIGEST_INTERVAL_SECS` (default 6 h, min 60 s). Shared by the
/// loop cadence and the effective-TTL derivation so they can't diverge.
fn digest_interval_secs() -> u64 {
    std::env::var("ML_DIGEST_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v >= 60)
        .unwrap_or(DEFAULT_DIGEST_INTERVAL_SECS)
}

/// Digest memory TTL, floored at [`DIGEST_TTL_HOURS`] and always at least
/// two refresh intervals so a single missed/late tick can't let the entry
/// expire out of the actor's memory (the pending items remain in
/// `ml_disagreements` regardless — this only governs the review surface).
fn effective_ttl_hours() -> f64 {
    let interval_hours = digest_interval_secs() as f64 / 3600.0;
    (interval_hours * 2.0).max(DIGEST_TTL_HOURS)
}

/// UTF-8-safe truncation for the preview.
fn preview(s: &str) -> String {
    if s.chars().count() <= PREVIEW_CHARS {
        return s.replace('\n', " · ");
    }
    let cut: String = s.chars().take(PREVIEW_CHARS).collect();
    format!("{}…", cut.replace('\n', " · "))
}

/// Spawn the digest loop. Interval from `ML_DIGEST_INTERVAL_SECS`
/// (default 6 h, min 60 s); observes the shared background-shutdown
/// watch.
pub fn spawn_disagreement_digest(
    pool: PgPool,
    lifecycle_service: std::sync::Arc<LifecycleService>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let interval_secs = digest_interval_secs();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tracing::info!(interval_secs, "ml disagreement-digest task active");
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    tracing::info!("ml disagreement-digest task shutting down");
                    break;
                }
                _ = interval.tick() => {
                    match run_digest_tick(&pool, &lifecycle_service).await {
                        Ok(n) if n > 0 => tracing::info!(delivered = n, "ml digest tick complete"),
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "ml digest tick failed; retrying next interval"),
                    }
                }
            }
        }
    });
}

/// One bounded tick. Public so an integration test can drive it
/// deterministically. Returns the number of digests actually delivered.
pub async fn run_digest_tick(pool: &PgPool, lifecycle_service: &LifecycleService) -> Result<usize> {
    // Least-recently-visited first so a fleet with more digest-configured
    // models than one tick's cap still cycles through all of them (the
    // rotation the evaluator uses; ordering by dataset/update recency
    // would permanently starve the tail). last_digest_at is stamped on
    // EVERY visit below.
    let rows = sqlx::query(
        "SELECT id, user_id, name, config_json FROM ml_models \
         WHERE policy_json <> '{}'::jsonb \
           AND config_json #>> '{digest,actor_id}' IS NOT NULL \
         ORDER BY last_digest_at ASC NULLS FIRST, id LIMIT $1",
    )
    .bind(MODELS_PER_TICK)
    .fetch_all(pool)
    .await
    .context("scan digest-configured models")?;

    let mut delivered = 0usize;
    for row in rows {
        let model_id: Uuid = row.try_get("id")?;
        // Stamp the visit FIRST (autocommit) so rotation advances even
        // when this model has nothing to deliver or delivery errors —
        // otherwise a model that always fails would pin the head of the
        // ASC-NULLS-FIRST scan and starve the rest.
        if let Err(e) = sqlx::query("UPDATE ml_models SET last_digest_at = NOW() WHERE id = $1")
            .bind(model_id)
            .execute(pool)
            .await
        {
            tracing::warn!(%model_id, error = %e, "failed to stamp last_digest_at");
        }
        match deliver_one(pool, lifecycle_service, &row).await {
            Ok(true) => delivered += 1,
            Ok(false) => {}
            Err(e) => tracing::warn!(%model_id, error = %e, "digest delivery failed for model"),
        }
    }
    Ok(delivered)
}

/// Returns Ok(true) when a digest was written, Ok(false) on a clean skip
/// (no configured actor owned by the user, or no pending disagreements).
async fn deliver_one(
    pool: &PgPool,
    lifecycle_service: &LifecycleService,
    row: &sqlx::postgres::PgRow,
) -> Result<bool> {
    let model_id: Uuid = row.try_get("id")?;
    let user_id: Uuid = row.try_get("user_id")?;
    let name: String = row.try_get("name")?;
    let config_json: serde_json::Value = row.try_get("config_json")?;

    let Some(digest_actor) = config_json
        .get("digest")
        .and_then(|d| d.get("actor_id"))
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
    else {
        return Ok(false);
    };
    // Tenancy: the digest actor MUST belong to the model's owner —
    // otherwise a misconfigured (or malicious) config could route one
    // tenant's decrypted email content into another tenant's memory.
    // `user_id` here is the MODEL's owner (from the scanned row), not
    // anything the config supplied — config only carries `actor_id`.
    // (Bounded TOCTOU: actor ownership could in principle be reassigned
    // between this check and the write below; actor-ownership transfer
    // is not a routine operation and the window is one read tx, so the
    // exposure is negligible — same caller-verifies contract as
    // talos_memory::clone_memories.)
    let actor_row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT user_id, status FROM actors WHERE id = $1")
            .bind(digest_actor)
            .fetch_optional(pool)
            .await
            .context("resolve digest actor owner")?;
    let actor_status = match actor_row {
        Some((owner, status)) if owner == user_id => status,
        _ => {
            tracing::warn!(
                %model_id,
                "digest actor is not owned by the model's user; skipping delivery"
            );
            return Ok(false);
        }
    };
    // A retired actor must stop RECEIVING data, not just stop acting —
    // archiving/terminating is often containment, and digests carry
    // decrypted email-derived previews. talos-memory checks org + tier on
    // persist but never status, so without this skip the tick keeps
    // accumulating sensitive content in a store the user believes is dead.
    if actor_status == "archived" || actor_status == "terminated" {
        tracing::warn!(
            %model_id,
            actor_status,
            "digest actor is retired; skipping delivery (point the model config's \
             digest.actor_id at an active actor to resume digests)"
        );
        return Ok(false);
    }

    // Read pending disagreements owner-scoped (RLS backstop + the
    // LifecycleService's own user_id predicate) and decrypted.
    let mut tx = talos_db::begin_tenant_read_scoped(
        pool,
        &talos_tenancy::TenantReadScope::new(user_id, Vec::new()),
    )
    .await
    .context("open digest read tx")?;
    let pending = lifecycle_service
        .pending_disagreements(&mut tx, model_id, user_id, DIGEST_ENTRIES)
        .await?;
    tx.commit().await.ok();
    if pending.is_empty() {
        return Ok(false);
    }

    let entries: Vec<serde_json::Value> = pending
        .iter()
        .map(|d| {
            serde_json::json!({
                "disagreement_id": d.id.to_string(),
                "kind": d.kind,
                "fast_label": d.fast_label,
                "fast_confidence": d.fast_confidence,
                "llm_label": d.llm_label,
                "preview": preview(&d.features_text),
            })
        })
        .collect();
    let digest = serde_json::json!({
        "model": name,
        "pending": entries.len(),
        "review_hint": "Label each entry by the category the email should ARRIVE in based \
                        on its content — not where you later filed it after acting (reading a \
                        'to_read' and then archiving it is NOT an 'archive' correction). Call \
                        ml_resolve_disagreement(disagreement_id, correct_label) to append a gold \
                        correction, or omit correct_label to dismiss. Corrections count toward \
                        the model's promotion policy.",
        "entries": entries,
    });

    // Keyed by model_id (NOT name): ml_models.name is unique only per
    // (user, personal) / (org) scope, so a user's same-named personal +
    // org model would collide on one key and silently overwrite each
    // other. The human-readable name rides in the value + metadata.
    //
    // `scratchpad` memory_type is deliberate (review 2026-07-12): it is
    // the one type the memory service does NOT embed. The digest carries
    // decrypted email-derived previews, and embedding them would ship
    // that content to the configured embedding provider — which, for a
    // tier-2 digest actor, can be EXTERNAL. ml_disagreements keeps the
    // full text encrypted-at-rest and never embeds; the digest must not
    // open a new egress surface for it. scratchpad is also excluded from
    // semantic recall / context injection, which is correct: the digest
    // is operational review data, not a memory.
    talos_memory::persist_memory_with_metadata(
        pool,
        digest_actor,
        &format!("ml_digest/{model_id}"),
        &digest,
        Some(&serde_json::json!({ "kind": "ml_digest", "model": name })),
        "scratchpad",
        Some(effective_ttl_hours()),
    )
    .await
    .context("write digest to actor_memory")?;

    tracing::info!(
        %model_id,
        %digest_actor,
        pending = entries.len(),
        "disagreement digest delivered"
    );
    Ok(true)
}
