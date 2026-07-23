//! # Autonomous memory consolidation (Phase 3b)
//!
//! A default-OFF background loop that summarizes an actor's OLD, COLD,
//! LOW-importance episodic memories via a TIER-GATED LLM and consolidates the
//! batch into ONE durable semantic summary (atomic persist-summary +
//! forget-sources, via [`talos_memory::consolidate_memory`]).
//!
//! ## The #1 security invariant
//! A **tier-1 actor** (`actors.max_llm_tier = 'tier1'`) has privacy-sensitive
//! memory that MUST NEVER reach an external LLM provider. Its summary is
//! generated on a **LOCAL Ollama model ONLY**, or SKIPPED entirely — fail
//! closed on an unknown/corrupt tier. The tier gate is the shared, pure
//! `talos_actor_repository::decide_llm_tier` matrix — the loop resolves it from
//! the scanned row via [`talos_actor_repository::llm_tier_decision_from_tier_str`]
//! (graph-RAG resolves the SAME matrix via its async
//! `resolve_llm_tier_decision`). The [`PlannedAction`] seam below makes
//! the routing unit-testable: an external `LlmClient` is constructed ONLY on
//! the [`PlannedAction::SummarizeExternal`] branch — never for a `LocalOnly` or
//! `Skip` actor.

use std::sync::Arc;

use sqlx::PgPool;
use talos_actor_repository::{ActorRepository, LlmTierDecision};
use talos_llm::OllamaClient;
use talos_secrets_manager::SecretsManager;
use tokio::sync::watch;

/// Max tokens for the consolidation summary generation (both backends).
const SUMMARY_MAX_TOKENS: u32 = 1024;

/// Batch-size floor: a candidate cluster smaller than this is not worth
/// consolidating (a trivial cluster isn't a "long tail"). Mirrors the config
/// clamp floor in [`talos_config::memory_consolidation_batch_size`].
const BATCH_FLOOR: i64 = 3;

/// What the loop plans to do for one actor, AFTER the tier gate and the
/// candidate scan. This is the security-critical routing seam: only
/// [`PlannedAction::SummarizeExternal`] is allowed to construct/consult an
/// external LLM. Kept pure ([`plan_action`]) so the routing is unit-testable
/// without Postgres, Ollama, or Anthropic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlannedAction {
    /// Do nothing — tier gate said Skip, or too few candidates to bother.
    /// NO LLM is constructed or consulted; NO mutation happens.
    Skip,
    /// Summarize on the LOCAL Ollama model only (tier-1, attested).
    SummarizeLocal,
    /// Summarize on the external provider (tier-2).
    SummarizeExternal,
}

/// Pure routing decision. `Skip` from the tier gate, OR fewer than `batch_floor`
/// candidates, both short-circuit to [`PlannedAction::Skip`]. Only a
/// tier-2 (`External`) actor with enough candidates routes to an external LLM.
pub fn plan_action(
    decision: LlmTierDecision,
    candidate_count: usize,
    batch_floor: i64,
) -> PlannedAction {
    if candidate_count < batch_floor.max(0) as usize {
        return PlannedAction::Skip;
    }
    match decision {
        LlmTierDecision::Skip => PlannedAction::Skip,
        LlmTierDecision::LocalOnly => PlannedAction::SummarizeLocal,
        LlmTierDecision::External => PlannedAction::SummarizeExternal,
    }
}

/// Build the (system, user) prompt for the consolidation summarizer.
/// Deterministic given the batch, so it's unit-testable. The batch of
/// `(key, value, memory_type)` rows is serialized compactly and capped so a
/// pathological batch can't blow the model's context.
pub fn build_consolidation_prompt(
    batch: &[(String, serde_json::Value, String)],
) -> (String, String) {
    let system = "You consolidate an AI assistant's older, low-importance memories into ONE concise durable summary. \
Preserve concrete facts, names, entities, dates, and commitments; drop redundancy and chatter. \
Return JSON {\"summary\": \"...\", \"key_facts\": [...]}."
        .to_string();

    // Serialize each row as {key, value}; cap the total user-prompt size so a
    // large batch can't produce an unbounded prompt.
    const MAX_USER_PROMPT_BYTES: usize = 24_000;
    let mut items = Vec::with_capacity(batch.len());
    for (key, value, _mtype) in batch {
        items.push(serde_json::json!({ "key": key, "value": value }));
    }
    let mut user = serde_json::to_string(&serde_json::json!({ "memories": items }))
        .unwrap_or_else(|_| "{\"memories\":[]}".to_string());
    if user.len() > MAX_USER_PROMPT_BYTES {
        // Truncate at a UTF-8 char boundary (never mid-codepoint).
        let mut end = MAX_USER_PROMPT_BYTES;
        while end > 0 && !user.is_char_boundary(end) {
            end -= 1;
        }
        user.truncate(end);
    }
    (system, user)
}

/// Parse the LLM summary output into the semantic value payload. Tolerant of
/// non-JSON output: a raw string that doesn't parse as a JSON object is wrapped
/// as `{"summary": <raw>}` so consolidation never fails on a chatty model.
pub fn parse_summary(raw: &str) -> serde_json::Value {
    let trimmed = raw.trim();
    match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(v) if v.is_object() => v,
        _ => serde_json::json!({ "summary": trimmed }),
    }
}

/// Deterministic semantic key for a consolidated summary:
/// `consolidated/<rfc3339-utc-timestamp>`. Uses the caller-supplied `now` so
/// the format is unit-testable.
pub fn build_semantic_key(now: chrono::DateTime<chrono::Utc>) -> String {
    format!("consolidated/{}", now.format("%Y%m%dT%H%M%S%.6fZ"))
}

/// Spawn the consolidation scheduler. Default-OFF: when
/// [`talos_config::memory_consolidation_enabled`] is false, logs once and
/// returns WITHOUT spawning a task (zero background overhead).
///
/// `ollama = None` disables the local backend (tier-1 actors then Skip); the
/// external path is unaffected. `actor_repo` need only carry the DB pool — the
/// tier gate is a plain `actors` read.
pub fn spawn_memory_consolidation_scheduler(
    pool: PgPool,
    actor_repo: ActorRepository,
    ollama: Option<Arc<OllamaClient>>,
    secrets_manager: Arc<SecretsManager>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    if !talos_config::memory_consolidation_enabled() {
        tracing::info!(
            target: "talos_memory_consolidation",
            "memory consolidation disabled (ENABLE_MEMORY_CONSOLIDATION unset); scheduler not spawned"
        );
        return;
    }

    let interval_secs = talos_config::memory_consolidation_interval_secs();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tracing::info!(
            target: "talos_memory_consolidation",
            interval_secs,
            ollama_configured = ollama.is_some(),
            tier1_local_ok = talos_config::memory_consolidation_tier1_local_ok(),
            "memory consolidation scheduler active"
        );
        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    tracing::info!(target: "talos_memory_consolidation", "memory consolidation scheduler shutting down");
                    break;
                }
                _ = interval.tick() => {
                    if let Err(e) = run_consolidation_tick(&pool, &actor_repo, ollama.as_ref(), &secrets_manager).await {
                        tracing::warn!(target: "talos_memory_consolidation", error = %e, "consolidation tick failed; retrying next interval");
                    }
                }
            }
        }
    });
}

/// One consolidation pass over the fleet. Scans up to
/// `max_actors_per_tick` active actors; for each, resolves the shared tier
/// decision, scans candidates, and — only when [`plan_action`] permits —
/// summarizes and atomically consolidates. Every LLM or parse failure logs and
/// continues with ZERO mutation (sources stay intact).
async fn run_consolidation_tick(
    pool: &PgPool,
    actor_repo: &ActorRepository,
    ollama: Option<&Arc<OllamaClient>>,
    secrets_manager: &Arc<SecretsManager>,
) -> anyhow::Result<()> {
    let tier1_local_ok = talos_config::memory_consolidation_tier1_local_ok();
    let min_age_days = talos_config::memory_consolidation_min_age_days();
    let max_importance = talos_config::memory_consolidation_max_importance();
    let batch_size = talos_config::memory_consolidation_batch_size();
    let max_actors = talos_config::memory_consolidation_max_actors_per_tick();
    let model = talos_config::memory_consolidation_model();

    let actors = actor_repo.scan_actors_for_consolidation(max_actors).await?;
    tracing::debug!(target: "talos_memory_consolidation", actor_count = actors.len(), "consolidation tick scanning actors");

    // Every actor the scan surfaced is stamped at the end of the tick so the
    // rotation cursor advances — whether it consolidated, skipped on the tier
    // gate, or had no candidates. Without this the sweep would revisit the same
    // lowest-cursor actors forever and starve the rest.
    let swept_ids: Vec<uuid::Uuid> = actors.iter().map(|a| a.actor_id).collect();

    for actor in actors {
        let actor_id = actor.actor_id;
        // Shared fail-closed tier gate — the SAME pure matrix graph-RAG uses
        // (`decide_llm_tier`), resolved from the tier already carried on the
        // scanned row (no per-actor tier lookup). A corrupt tier string maps to
        // Tier1 → Skip; it can never yield External.
        let decision = talos_actor_repository::llm_tier_decision_from_tier_str(
            &actor.max_llm_tier,
            tier1_local_ok,
            ollama.is_some(),
        );

        // Scan candidates (episodic + old + cold + low/unscored importance).
        let candidates = match talos_memory::scan_consolidation_candidates(
            pool,
            actor_id,
            min_age_days,
            max_importance,
            batch_size,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(target: "talos_memory_consolidation", %actor_id, error = %e, "candidate scan failed; skipping actor");
                continue;
            }
        };

        let action = plan_action(decision, candidates.len(), BATCH_FLOOR);
        if action == PlannedAction::Skip {
            tracing::debug!(
                target: "talos_memory_consolidation",
                %actor_id,
                ?decision,
                candidates = candidates.len(),
                "skipping actor (tier gate Skip or too few candidates); no LLM, no mutation"
            );
            continue;
        }

        // Take up to `batch_size` (scan already LIMITed to batch_size).
        let batch: Vec<_> = candidates;
        let (system, user) = build_consolidation_prompt(&batch);

        // Generate the summary. SECURITY: the external `LlmClient` is
        // constructed ONLY on the SummarizeExternal branch — a LocalOnly/Skip
        // actor's content never reaches Anthropic.
        let raw = match action {
            PlannedAction::SummarizeLocal => {
                let Some(ollama) = ollama else {
                    // plan_action only returns SummarizeLocal when ollama was
                    // wired (ollama.is_some() fed the tier gate), so this is
                    // unreachable; fail closed regardless.
                    tracing::warn!(target: "talos_memory_consolidation", %actor_id, "local summarize planned but ollama unavailable; skipping");
                    continue;
                };
                match ollama
                    .complete_structured(&model, &system, &user, SUMMARY_MAX_TOKENS)
                    .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(target: "talos_memory_consolidation", %actor_id, error = %e, "local LLM summarize failed; no mutation");
                        continue;
                    }
                }
            }
            PlannedAction::SummarizeExternal => {
                let client = talos_llm::LlmClient::with_vault(secrets_manager.clone(), None);
                match client.generate_text(&system, &user).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(target: "talos_memory_consolidation", %actor_id, error = %e, "external LLM summarize failed; no mutation");
                        continue;
                    }
                }
            }
            PlannedAction::Skip => continue, // handled above; unreachable
        };

        let source_count = batch.len();
        let semantic_value = parse_summary(&raw);
        let semantic_key = build_semantic_key(chrono::Utc::now());
        // metadata.kind = "consolidated". NOTE: "consolidated" is deliberately
        // NOT added to talos_memory::SYNTHETIC_MEMORY_KINDS — a consolidated
        // summary REPLACES real past content and SHOULD be recalled; it is not
        // a fresh synthetic self-inference to filter out.
        let metadata = serde_json::json!({ "kind": "consolidated", "source_count": source_count });
        let source_keys: Vec<String> = batch.into_iter().map(|(k, _v, _t)| k).collect();

        match talos_memory::consolidate_memory(
            pool,
            actor_id,
            &semantic_key,
            semantic_value,
            &source_keys,
            Some(metadata),
        )
        .await
        {
            Ok(retired) => tracing::info!(
                target: "talos_memory_consolidation",
                %actor_id,
                source_count,
                retired_count = retired,
                semantic_key = %semantic_key,
                "consolidated episodic memories into one semantic summary"
            ),
            Err(e) => {
                tracing::warn!(target: "talos_memory_consolidation", %actor_id, error = %e, "consolidate_memory failed; sources intact")
            }
        }
    }

    // Advance the rotation cursor for every actor this tick examined so the
    // next tick moves on to the least-recently-swept actors (fair fleet
    // coverage). Best-effort — a failure only means a repeat next tick.
    if let Err(e) = actor_repo.mark_actors_consolidated(&swept_ids).await {
        tracing::warn!(target: "talos_memory_consolidation", error = %e, "failed to advance consolidation rotation cursor");
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════
// Phase 3: the REFLECTION loop
//
// A daily per-actor background loop that reads across an actor's meaningful
// (semantic+episodic) memories and synthesizes HIGHER-ORDER INSIGHTS —
// recurring themes, evolving priorities, relationships, open threads — via the
// SAME tier-gated LLM matrix as consolidation. Unlike consolidation it is
// NON-DESTRUCTIVE: it writes ONE new `reflection`-kind semantic memory and
// deletes NOTHING (reflection AUGMENTS; consolidation retires). The input scan
// EXCLUDES prior reflections (and all synthetic kinds) so the loop never
// reflects on its own inferences (drift guard), and `"reflection"` is in
// `talos_memory::SYNTHETIC_MEMORY_KINDS` so reflections are excluded from
// grounding recall (feedback-amplification guard).
//
// The tier gate is REUSED VERBATIM (`plan_action` / `PlannedAction` /
// `llm_tier_decision_from_tier_str`): a tier-1 actor's memory is reflected on
// LOCAL Ollama ONLY, or Skipped — the external `LlmClient` is constructed ONLY
// on the `SummarizeExternal` branch, exactly as in consolidation.
// ════════════════════════════════════════════════════════════════════════

/// Max tokens for the reflection generation (both backends). Larger than the
/// consolidation summary — reflection emits a structured multi-field insight
/// set, not one paragraph.
const REFLECTION_MAX_TOKENS: u32 = 1536;

/// The single durable reflection key per actor. OVERWRITTEN each cycle (the
/// `ON CONFLICT (actor_id, key)` upsert in `persist_reflection` refreshes it)
/// so reflections don't accumulate unboundedly — mirrors `daily_brief/latest`.
const REFLECTION_KEY: &str = "reflection/latest";

/// Build the (system, user) prompt for the reflection synthesizer.
/// Deterministic given the memory set (unit-testable). The set of
/// `(key, value, memory_type)` rows is serialized compactly and byte-capped so
/// a pathological actor can't blow the model's context (same cap shape as
/// [`build_consolidation_prompt`]).
pub fn build_reflection_prompt(
    memories: &[(String, serde_json::Value, String)],
) -> (String, String) {
    let system = "You are a reflective analyst studying a person's accumulated work/life memories. \
Identify HIGHER-ORDER INSIGHTS — recurring themes, evolving priorities/goals, relationships between \
people/projects, and open threads/loose ends. Do NOT merely summarize; INFER what matters and what's \
changing. Return JSON: {\"insights\": [\"...\"], \"themes\": [\"...\"], \"open_threads\": [\"...\"]}."
        .to_string();

    const MAX_USER_PROMPT_BYTES: usize = 24_000;
    let mut items = Vec::with_capacity(memories.len());
    for (key, value, _mtype) in memories {
        items.push(serde_json::json!({ "key": key, "value": value }));
    }
    let mut user = serde_json::to_string(&serde_json::json!({ "memories": items }))
        .unwrap_or_else(|_| "{\"memories\":[]}".to_string());
    if user.len() > MAX_USER_PROMPT_BYTES {
        let mut end = MAX_USER_PROMPT_BYTES;
        while end > 0 && !user.is_char_boundary(end) {
            end -= 1;
        }
        user.truncate(end);
    }
    (system, user)
}

/// Parse the LLM reflection output into the semantic value payload. Tolerant of
/// non-JSON output: a raw string that doesn't parse as a JSON object is wrapped
/// as `{"insights": [<raw>]}` so reflection never fails on a chatty model.
pub fn parse_reflection(raw: &str) -> serde_json::Value {
    let trimmed = raw.trim();
    match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(v) if v.is_object() => v,
        _ => serde_json::json!({ "insights": [trimmed] }),
    }
}

/// Spawn the reflection scheduler. Default-OFF: when
/// [`talos_config::memory_reflection_enabled`] is false, logs once and returns
/// WITHOUT spawning a task (zero background overhead).
///
/// `ollama = None` disables the local backend (tier-1 actors then Skip); the
/// external path is unaffected.
pub fn spawn_memory_reflection_scheduler(
    pool: PgPool,
    actor_repo: ActorRepository,
    ollama: Option<Arc<OllamaClient>>,
    secrets_manager: Arc<SecretsManager>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    if !talos_config::memory_reflection_enabled() {
        tracing::info!(
            target: "talos_memory_reflection",
            "memory reflection disabled (ENABLE_MEMORY_REFLECTION unset); scheduler not spawned"
        );
        return;
    }

    // Misconfiguration guard: if the input cap is below the min-memories floor,
    // `scan_reflection_input` can never return enough rows to clear the floor,
    // so reflection silently no-ops for every actor. Warn loudly rather than
    // leaving the operator to wonder why nothing reflects.
    let cap = talos_config::memory_reflection_input_cap();
    let min = talos_config::memory_reflection_min_memories();
    if cap < min {
        tracing::warn!(
            target: "talos_memory_reflection",
            input_cap = cap,
            min_memories = min,
            "MEMORY_REFLECTION_INPUT_CAP < MEMORY_REFLECTION_MIN_MEMORIES — reflection will \
             never reach the floor and no actor will ever be reflected; raise the input cap"
        );
    }

    let interval_secs = talos_config::memory_reflection_interval_secs();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tracing::info!(
            target: "talos_memory_reflection",
            interval_secs,
            ollama_configured = ollama.is_some(),
            tier1_local_ok = talos_config::memory_reflection_tier1_local_ok(),
            "memory reflection scheduler active"
        );
        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    tracing::info!(target: "talos_memory_reflection", "memory reflection scheduler shutting down");
                    break;
                }
                _ = interval.tick() => {
                    if let Err(e) = run_reflection_tick(&pool, &actor_repo, ollama.as_ref(), &secrets_manager).await {
                        tracing::warn!(target: "talos_memory_reflection", error = %e, "reflection tick failed; retrying next interval");
                    }
                }
            }
        }
    });
}

/// One reflection pass over the fleet. Scans up to `max_actors_per_tick` active
/// actors (least-recently-reflected first); for each, resolves the shared tier
/// decision, scans meaningful memories, and — only when [`plan_action`] permits
/// — synthesizes insights and writes ONE non-destructive reflection. Every LLM,
/// parse, or write failure logs and continues with ZERO source deletion (there
/// are no sources to delete — reflection never deletes).
async fn run_reflection_tick(
    pool: &PgPool,
    actor_repo: &ActorRepository,
    ollama: Option<&Arc<OllamaClient>>,
    secrets_manager: &Arc<SecretsManager>,
) -> anyhow::Result<()> {
    let tier1_local_ok = talos_config::memory_reflection_tier1_local_ok();
    let input_cap = talos_config::memory_reflection_input_cap();
    let min_memories = talos_config::memory_reflection_min_memories();
    let max_actors = talos_config::memory_reflection_max_actors_per_tick();
    let model = talos_config::memory_reflection_model();
    let exclude_kinds = talos_memory::synthetic_memory_kinds();

    let actors = actor_repo.scan_actors_for_reflection(max_actors).await?;
    tracing::debug!(target: "talos_memory_reflection", actor_count = actors.len(), "reflection tick scanning actors");

    // Every actor the scan surfaced is stamped at tick end so the rotation
    // cursor advances — whether it reflected, skipped on the tier gate, or had
    // too few memories. Without this the sweep would revisit the same
    // lowest-cursor actors forever and starve the rest.
    let swept_ids: Vec<uuid::Uuid> = actors.iter().map(|a| a.actor_id).collect();

    for actor in actors {
        let actor_id = actor.actor_id;
        // Shared fail-closed tier gate — the SAME pure matrix consolidation and
        // graph-RAG use. A corrupt tier string maps to Tier1 → Skip; it can
        // never yield External.
        let decision = talos_actor_repository::llm_tier_decision_from_tier_str(
            &actor.max_llm_tier,
            tier1_local_ok,
            ollama.is_some(),
        );

        // Scan meaningful memories (semantic+episodic, synthetic+reflection
        // EXCLUDED — reflecting on prior reflections would drift).
        let memories = match talos_memory::scan_reflection_input(
            pool,
            actor_id,
            &exclude_kinds,
            input_cap,
        )
        .await
        {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(target: "talos_memory_reflection", %actor_id, error = %e, "reflection input scan failed; skipping actor");
                continue;
            }
        };

        let action = plan_action(decision, memories.len(), min_memories);
        if action == PlannedAction::Skip {
            tracing::debug!(
                target: "talos_memory_reflection",
                %actor_id,
                ?decision,
                memories = memories.len(),
                "skipping actor (tier gate Skip or too few memories); no LLM, no write"
            );
            continue;
        }

        let (system, user) = build_reflection_prompt(&memories);

        // Generate the reflection. SECURITY: the external `LlmClient` is
        // constructed ONLY on the SummarizeExternal branch — a LocalOnly/Skip
        // actor's content never reaches Anthropic.
        let raw = match action {
            PlannedAction::SummarizeLocal => {
                let Some(ollama) = ollama else {
                    tracing::warn!(target: "talos_memory_reflection", %actor_id, "local reflection planned but ollama unavailable; skipping");
                    continue;
                };
                match ollama
                    .complete_structured(&model, &system, &user, REFLECTION_MAX_TOKENS)
                    .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(target: "talos_memory_reflection", %actor_id, error = %e, "local LLM reflection failed; no write");
                        continue;
                    }
                }
            }
            PlannedAction::SummarizeExternal => {
                let client = talos_llm::LlmClient::with_vault(secrets_manager.clone(), None);
                match client.generate_text(&system, &user).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(target: "talos_memory_reflection", %actor_id, error = %e, "external LLM reflection failed; no write");
                        continue;
                    }
                }
            }
            PlannedAction::Skip => continue, // handled above; unreachable
        };

        let source_count = memories.len();
        let value = parse_reflection(&raw);
        let metadata = serde_json::json!({
            "kind": "reflection",
            "source_count": source_count,
            "reflected_at": chrono::Utc::now().to_rfc3339(),
        });

        // NON-DESTRUCTIVE write: one new semantic memory at `reflection/latest`,
        // encrypted via the per-org DEK/AAD path. NOTHING is deleted.
        match talos_memory::persist_reflection(pool, actor_id, REFLECTION_KEY, value, metadata)
            .await
        {
            Ok(()) => tracing::info!(
                target: "talos_memory_reflection",
                %actor_id,
                source_count,
                reflection_key = REFLECTION_KEY,
                "wrote reflection insight (non-destructive; sources intact)"
            ),
            Err(e) => {
                tracing::warn!(target: "talos_memory_reflection", %actor_id, error = %e, "persist_reflection failed; no write")
            }
        }
    }

    // Advance the reflection rotation cursor for every actor this tick examined
    // so the next tick moves on to the least-recently-reflected actors.
    // Best-effort — a failure only means a repeat next tick.
    if let Err(e) = actor_repo.mark_actors_reflected(&swept_ids).await {
        tracing::warn!(target: "talos_memory_reflection", error = %e, "failed to advance reflection rotation cursor");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_action_skip_decision_never_summarizes() {
        // A Skip tier decision NEVER summarizes, regardless of candidate count.
        assert_eq!(
            plan_action(LlmTierDecision::Skip, 100, BATCH_FLOOR),
            PlannedAction::Skip
        );
    }

    #[test]
    fn plan_action_too_few_candidates_skips() {
        // Even a tier-2 actor with fewer than the floor is skipped (no LLM).
        assert_eq!(
            plan_action(LlmTierDecision::External, 2, BATCH_FLOOR),
            PlannedAction::Skip
        );
        assert_eq!(
            plan_action(LlmTierDecision::LocalOnly, 2, BATCH_FLOOR),
            PlannedAction::Skip
        );
    }

    #[test]
    fn plan_action_local_only_routes_local() {
        // The security-critical routing: LocalOnly NEVER routes external.
        assert_eq!(
            plan_action(LlmTierDecision::LocalOnly, 10, BATCH_FLOOR),
            PlannedAction::SummarizeLocal
        );
    }

    #[test]
    fn plan_action_external_routes_external() {
        assert_eq!(
            plan_action(LlmTierDecision::External, 10, BATCH_FLOOR),
            PlannedAction::SummarizeExternal
        );
    }

    #[test]
    fn plan_action_at_floor_boundary() {
        // Exactly at the floor is enough; one below is not.
        assert_eq!(
            plan_action(LlmTierDecision::External, 3, 3),
            PlannedAction::SummarizeExternal
        );
        assert_eq!(
            plan_action(LlmTierDecision::External, 2, 3),
            PlannedAction::Skip
        );
    }

    #[test]
    fn parse_summary_valid_json_object() {
        let v = parse_summary("{\"summary\": \"did X\", \"key_facts\": [\"a\"]}");
        assert_eq!(v["summary"], "did X");
        assert_eq!(v["key_facts"][0], "a");
    }

    #[test]
    fn parse_summary_non_json_wraps_as_summary() {
        let v = parse_summary("The user prefers dark mode and lives in Halifax.");
        assert_eq!(
            v["summary"],
            "The user prefers dark mode and lives in Halifax."
        );
    }

    #[test]
    fn parse_summary_json_array_wraps_as_summary() {
        // A non-object JSON value (array/scalar) is wrapped, not passed through.
        let v = parse_summary("[1, 2, 3]");
        assert!(v.is_object());
        assert_eq!(v["summary"], "[1, 2, 3]");
    }

    #[test]
    fn semantic_key_format() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-22T12:34:56.123456Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let key = build_semantic_key(now);
        assert!(key.starts_with("consolidated/"));
        assert!(key.contains("20260722T123456"));
    }

    #[test]
    fn prompt_is_deterministic_and_bounded() {
        let batch = vec![
            (
                "k1".to_string(),
                serde_json::json!({"note": "met Alice"}),
                "episodic".to_string(),
            ),
            (
                "k2".to_string(),
                serde_json::json!({"note": "met Bob"}),
                "episodic".to_string(),
            ),
        ];
        let (s1, u1) = build_consolidation_prompt(&batch);
        let (s2, u2) = build_consolidation_prompt(&batch);
        assert_eq!(s1, s2);
        assert_eq!(u1, u2);
        assert!(s1.contains("Return JSON"));
        assert!(u1.contains("met Alice"));
        assert!(u1.contains("met Bob"));
    }

    #[test]
    fn prompt_truncates_oversized_batch() {
        // A huge value must not produce an unbounded prompt.
        let big = "x".repeat(100_000);
        let batch = vec![(
            "k".to_string(),
            serde_json::json!({ "v": big }),
            "episodic".to_string(),
        )];
        let (_s, u) = build_consolidation_prompt(&batch);
        assert!(u.len() <= 24_000);
    }

    // ── Reflection helpers ──────────────────────────────────────────────

    #[test]
    fn reflection_plan_action_reuses_tier_gate() {
        // The reflection loop reuses `plan_action` verbatim: a tier-1 actor
        // whose gate resolves LocalOnly NEVER routes external; a Skip gate
        // never summarizes regardless of memory count; the floor is
        // min_memories.
        assert_eq!(
            plan_action(LlmTierDecision::LocalOnly, 10, 8),
            PlannedAction::SummarizeLocal
        );
        assert_eq!(
            plan_action(LlmTierDecision::Skip, 100, 8),
            PlannedAction::Skip
        );
        assert_eq!(
            plan_action(LlmTierDecision::External, 7, 8),
            PlannedAction::Skip // below the min-memories floor
        );
        assert_eq!(
            plan_action(LlmTierDecision::External, 8, 8),
            PlannedAction::SummarizeExternal
        );
    }

    #[test]
    fn parse_reflection_valid_json_object() {
        let v = parse_reflection(
            "{\"insights\": [\"prioritizes X\"], \"themes\": [\"growth\"], \"open_threads\": [\"Y\"]}",
        );
        assert_eq!(v["insights"][0], "prioritizes X");
        assert_eq!(v["themes"][0], "growth");
        assert_eq!(v["open_threads"][0], "Y");
    }

    #[test]
    fn parse_reflection_non_json_wraps_as_insight() {
        let v = parse_reflection("The user is shifting focus toward platform reliability.");
        assert!(v.is_object());
        assert_eq!(
            v["insights"][0],
            "The user is shifting focus toward platform reliability."
        );
    }

    #[test]
    fn parse_reflection_json_array_wraps() {
        // A non-object JSON value is wrapped, not passed through.
        let v = parse_reflection("[1, 2, 3]");
        assert!(v.is_object());
        assert_eq!(v["insights"][0], "[1, 2, 3]");
    }

    #[test]
    fn reflection_prompt_is_deterministic_and_bounded() {
        let memories = vec![
            (
                "note/1".to_string(),
                serde_json::json!({"note": "shipped auth refactor"}),
                "episodic".to_string(),
            ),
            (
                "pref/mode".to_string(),
                serde_json::json!({"pref": "prefers async reviews"}),
                "semantic".to_string(),
            ),
        ];
        let (s1, u1) = build_reflection_prompt(&memories);
        let (s2, u2) = build_reflection_prompt(&memories);
        assert_eq!(s1, s2);
        assert_eq!(u1, u2);
        assert!(s1.contains("HIGHER-ORDER INSIGHTS"));
        assert!(s1.contains("open_threads"));
        assert!(u1.contains("shipped auth refactor"));
        assert!(u1.contains("prefers async reviews"));
    }

    #[test]
    fn reflection_prompt_truncates_oversized_input() {
        let big = "x".repeat(100_000);
        let memories = vec![(
            "k".to_string(),
            serde_json::json!({ "v": big }),
            "semantic".to_string(),
        )];
        let (_s, u) = build_reflection_prompt(&memories);
        assert!(u.len() <= 24_000);
    }

    #[test]
    fn reflection_key_is_stable_latest() {
        // The single-latest overwrite key must not drift.
        assert_eq!(REFLECTION_KEY, "reflection/latest");
    }
}
