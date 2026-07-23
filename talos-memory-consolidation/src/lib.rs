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

/// JSON Schema for the consolidation output contract `{summary, key_facts}`.
/// Feeds BOTH structured-output paths: the Ollama `format` field (local, tier-1)
/// and the Anthropic tool `input_schema` (external, tier-2). Schema-constraining
/// the output is what makes the summary reliably parseable — the prior
/// `format:"json"` (Ollama) / prompt-and-parse (Anthropic) modes only guaranteed
/// valid JSON *syntax*, not this *shape*, so a model could return the whole
/// payload under the wrong key and `parse_summary` would silently wrap it.
pub fn consolidation_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "ONE concise durable summary of the consolidated memories."
            },
            "key_facts": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Concrete facts, names, entities, dates, and commitments worth preserving."
            }
        },
        "required": ["summary", "key_facts"]
    })
}

/// Best-effort recovery of a JSON OBJECT from an LLM completion. Local models
/// (Ollama) frequently wrap structured output in ways a bare `from_str` rejects,
/// silently collapsing the payload into a fallback field and LOSING the real
/// structure (e.g. dropping the synthesized `entities`). This handles the common
/// cases:
/// 1. plain object — parse as-is;
/// 2. markdown code fence (```json … ```) or leading/trailing prose — slice the
///    outermost `{ … }` and parse that;
/// 3. double-encoded — the model returned the object as a JSON *string*; decode
///    once more.
/// Returns `None` when no object can be recovered (the caller applies its own
/// tolerant wrap).
pub fn coerce_json_object(raw: &str) -> Option<serde_json::Value> {
    let trimmed = raw.trim();
    // (1) direct
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if v.is_object() {
            return Some(v);
        }
        // (3) double-encoded: a JSON string whose contents are the object.
        if let serde_json::Value::String(s) = &v {
            if let Ok(inner) = serde_json::from_str::<serde_json::Value>(s.trim()) {
                if inner.is_object() {
                    return Some(inner);
                }
            }
        }
    }
    // (2) slice the outermost {...} (strips code fences / prose on both sides).
    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if end > start {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&trimmed[start..=end]) {
                if v.is_object() {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Parse the LLM summary output into the semantic value payload. Tolerant of
/// non-JSON output: a raw string that doesn't recover to a JSON object is
/// wrapped as `{"summary": <raw>}` so consolidation never fails on a chatty model.
pub fn parse_summary(raw: &str) -> serde_json::Value {
    coerce_json_object(raw).unwrap_or_else(|| serde_json::json!({ "summary": raw.trim() }))
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
                    .complete_with_schema(
                        &model,
                        &system,
                        &user,
                        SUMMARY_MAX_TOKENS,
                        &consolidation_schema(),
                    )
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
                match client
                    .generate_with_schema(
                        &system,
                        &user,
                        &consolidation_schema(),
                        "record_consolidation",
                    )
                    .await
                {
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

/// Max serialized bytes of the entity-graph context folded into the
/// reflection user prompt. Kept well below the overall prompt cap so the
/// flat memory rows stay the dominant signal even when an actor has a large
/// accumulated graph (`get_graph_context` is itself node-capped, but this is
/// the belt-and-suspenders bound). Truncation is at a char boundary.
const MAX_GRAPH_CONTEXT_BYTES: usize = 8_000;

/// Build the (system, user) prompt for the reflection synthesizer.
/// Deterministic given the memory set + optional graph context
/// (unit-testable). The `(key, value, memory_type)` rows are serialized
/// compactly and byte-capped so a pathological actor can't blow the model's
/// context (same cap shape as [`build_consolidation_prompt`]).
///
/// Phase 4 (graph-aware reflection + entity synthesis):
/// * `graph_context` — when `Some`, the actor's CURRENT entity graph
///   (`talos_graph_rag::GraphRagService::get_graph_context` output:
///   `{entities: [{type, name, relationships: [...]}], ...}`) is folded in as
///   CONTEXT so the LLM reasons over accumulated multi-hop relationships
///   (Person → owns → Project → blocked-by → …), not just flat rows. `None`
///   (graph unavailable / empty / errored) degrades gracefully to the
///   flat-memory-only prompt.
/// * The JSON contract additionally requests durable `entities` — curated
///   entity facts + relationships the caller upserts into the graph as
///   first-class nodes (the deliberate curated path that replaces the generic
///   auto-extraction the graph-write policy now skips for reflections).
pub fn build_reflection_prompt(
    memories: &[(String, serde_json::Value, String)],
    graph_context: Option<&serde_json::Value>,
) -> (String, String) {
    let system = "You are a reflective analyst studying a person's accumulated work/life memories. \
Identify HIGHER-ORDER INSIGHTS — recurring themes, evolving priorities/goals, relationships between \
people/projects, and open threads/loose ends. Do NOT merely summarize; INFER what matters and what's \
changing. When an ENTITY GRAPH is provided, reason OVER the accumulated relationships (multi-hop: \
Person → owns → Project → blocked-by → …), not just the flat memory rows. ALSO extract durable ENTITY \
FACTS worth remembering as first-class graph nodes. Return JSON: {\"insights\": [\"...\"], \
\"themes\": [\"...\"], \"open_threads\": [\"...\"], \"entities\": [{\"name\": \"...\", \
\"type\": \"Person|Project|Ticket|Concept|Organization|...\", \"facts\": [\"...\"], \
\"relationships\": [{\"type\": \"WORKS_ON|BLOCKED_BY|OWNS|ASSIGNED_TO|RELATED_TO|...\", \
\"target\": \"...\"}]}]}."
        .to_string();

    const MAX_USER_PROMPT_BYTES: usize = 24_000;
    let mut items = Vec::with_capacity(memories.len());
    for (key, value, _mtype) in memories {
        items.push(serde_json::json!({ "key": key, "value": value }));
    }

    // Fold in the current entity graph as CONTEXT, separately byte-capped so
    // it never crowds out the memory rows. Best-effort: on serialization
    // failure or absence, `entity_graph` is null and the prompt degrades to
    // the flat-memory-only shape.
    let entity_graph: serde_json::Value = match graph_context {
        Some(g) => {
            let s = serde_json::to_string(g).unwrap_or_default();
            if s.len() > MAX_GRAPH_CONTEXT_BYTES {
                // Too large to fold verbatim; pass a compact marker rather
                // than a truncated (invalid) JSON blob.
                serde_json::json!({ "note": "entity graph omitted (too large)" })
            } else {
                g.clone()
            }
        }
        None => serde_json::Value::Null,
    };

    let mut user = serde_json::to_string(
        &serde_json::json!({ "memories": items, "entity_graph": entity_graph }),
    )
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

/// JSON Schema for the reflection output contract
/// `{insights, themes, open_threads, entities:[{name,type,facts,relationships}]}`.
/// Feeds BOTH structured-output paths (Ollama `format` / Anthropic tool
/// `input_schema`). Schema-constraining the nested `entities` shape is the
/// direct fix for the flaky local-model output observed in live testing —
/// qwen sometimes double-encoded the whole reply into `insights[0]`, yielding
/// zero synthesized entities. `parse_reflection` / `parse_reflection_entities`
/// remain tolerant as belt-and-suspenders, but the schema makes the
/// well-formed shape the *default* rather than the lucky case.
pub fn reflection_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "insights": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Higher-order inferences about what matters and what is changing (not mere summary)."
            },
            "themes": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Recurring themes across the memories."
            },
            "open_threads": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Unresolved threads / loose ends."
            },
            "entities": {
                "type": "array",
                "description": "Durable entity facts worth remembering as first-class graph nodes.",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "type": {
                            "type": "string",
                            "description": "Person|Project|Ticket|Concept|Organization|..."
                        },
                        "facts": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "relationships": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "type": {
                                        "type": "string",
                                        "description": "WORKS_ON|BLOCKED_BY|OWNS|ASSIGNED_TO|RELATED_TO|..."
                                    },
                                    "target": { "type": "string" }
                                },
                                "required": ["type", "target"]
                            }
                        }
                    },
                    "required": ["name", "type", "facts"]
                }
            }
        },
        "required": ["insights", "themes", "open_threads", "entities"]
    })
}

/// Parsed synthesized entity from a reflection output's `entities` array —
/// the durable graph-facts contract. `parse_reflection_entities` is tolerant:
/// a missing/malformed `entities` field yields an empty Vec so reflection
/// never fails on a model that ignored the entity contract.
#[derive(Debug, Clone, PartialEq)]
pub struct SynthesizedEntity {
    pub name: String,
    pub entity_type: String,
    pub facts: Vec<String>,
    pub relationships: Vec<SynthesizedRelationship>,
}

/// One relationship on a [`SynthesizedEntity`] — `(predicate, target-name)`.
#[derive(Debug, Clone, PartialEq)]
pub struct SynthesizedRelationship {
    pub predicate: String,
    pub target: String,
}

/// Extract the durable `entities` list from a parsed reflection value.
/// TOLERANT by design (Phase 4 contract): a missing `entities` key, a
/// non-array value, or entries missing `name` yield an empty / filtered
/// result — the graph enrichment is best-effort and must never fail the
/// reflection memory write. Entries with an empty `name` are dropped.
/// Pure — unit-tested without a live graph.
pub fn parse_reflection_entities(value: &serde_json::Value) -> Vec<SynthesizedEntity> {
    let Some(arr) = value.get("entities").and_then(|e| e.as_array()) else {
        return Vec::new();
    };
    // Cap the node key (name) and relationship targets — they become MERGE
    // identities, so an oversized value is an ugly (token-bounded, but still
    // unbounded-in-principle) graph key. `.chars().take()` is char-safe.
    const MAX_NAME_CHARS: usize = 160;
    let cap_name = |s: &str| -> String { s.trim().chars().take(MAX_NAME_CHARS).collect() };

    let mut out = Vec::new();
    for e in arr {
        let name = cap_name(e.get("name").and_then(|n| n.as_str()).unwrap_or_default());
        if name.is_empty() {
            continue;
        }
        let entity_type = e
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("Concept")
            .to_string();
        let facts = e
            .get("facts")
            .and_then(|f| f.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|f| f.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let relationships = e
            .get("relationships")
            .and_then(|r| r.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|r| {
                        let predicate = r.get("type").and_then(|t| t.as_str()).unwrap_or_default();
                        let target = r.get("target").and_then(|t| t.as_str()).unwrap_or_default();
                        if predicate.is_empty() || target.trim().is_empty() {
                            return None;
                        }
                        Some(SynthesizedRelationship {
                            predicate: predicate.to_string(),
                            target: cap_name(target),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.push(SynthesizedEntity {
            name,
            entity_type,
            facts,
            relationships,
        });
    }
    out
}

/// Parse the LLM reflection output into the semantic value payload. Tolerant of
/// non-JSON output: a raw string that doesn't parse as a JSON object is wrapped
/// as `{"insights": [<raw>]}` so reflection never fails on a chatty model.
pub fn parse_reflection(raw: &str) -> serde_json::Value {
    coerce_json_object(raw).unwrap_or_else(|| serde_json::json!({ "insights": [raw.trim()] }))
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

        // GRAPH-AWARE REFLECTION (Phase 4): fetch the actor's CURRENT entity
        // graph so the LLM reasons over accumulated multi-hop relationships,
        // not just flat memory rows. Best-effort + ACTOR-SCOPED: every read in
        // `get_graph_context` is `WHERE n.actor_id=$actor_id`; on any error /
        // no graph handle, we proceed WITHOUT it (the prompt degrades to
        // flat-memory-only). Only fetched for actors that will actually reflect
        // (post-gate) — no graph query for skipped actors.
        let graph_context = fetch_reflection_graph_context(actor_id, &memories).await;

        let (system, user) = build_reflection_prompt(&memories, graph_context.as_ref());

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
                    .complete_with_schema(
                        &model,
                        &system,
                        &user,
                        REFLECTION_MAX_TOKENS,
                        &reflection_schema(),
                    )
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
                match client
                    .generate_with_schema(&system, &user, &reflection_schema(), "record_reflection")
                    .await
                {
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

        // DELIBERATE ENTITY SYNTHESIS (Phase 4): parse the durable entity facts
        // out of the SAME tier-gated completion BEFORE the memory value is
        // moved into `persist_reflection`. These reach the graph ONLY via the
        // curated `upsert_entity` path below — the generic auto-extraction is
        // now SKIPPED for `kind = "reflection"` (graph-write policy), so this
        // is the one high-quality signal replacing the noisy auto-mining.
        let entities = parse_reflection_entities(&value);

        // NON-DESTRUCTIVE write: one new semantic memory at `reflection/latest`,
        // encrypted via the per-org DEK/AAD path. NOTHING is deleted. This is
        // the PRIMARY output — it must not fail because of graph issues.
        let reflection_written = match talos_memory::persist_reflection(
            pool,
            actor_id,
            REFLECTION_KEY,
            value,
            metadata,
        )
        .await
        {
            Ok(()) => {
                tracing::info!(
                    target: "talos_memory_reflection",
                    %actor_id,
                    source_count,
                    reflection_key = REFLECTION_KEY,
                    "wrote reflection insight (non-destructive; sources intact)"
                );
                true
            }
            Err(e) => {
                tracing::warn!(target: "talos_memory_reflection", %actor_id, error = %e, "persist_reflection failed; no write");
                false
            }
        };

        // Upsert the synthesized entities into the actor's graph as first-class
        // nodes — ONLY when the reflection memory actually landed (don't
        // half-apply a reflection's graph side effects when its own row failed).
        // Best-effort, ACTOR-SCOPED, and needs NO additional tier gate: the
        // entity list came from the reflection completion that was ALREADY
        // tier-gated (a tier-1 actor's synthesis ran on LOCAL Ollama), and the
        // write itself is a Neo4j MERGE — no LLM, no external egress.
        if reflection_written {
            persist_synthesized_entities(actor_id, &entities).await;
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

/// Build a fulltext hint for `get_graph_context` from the actor's recent
/// memory keys — seeds the multi-hop traversal toward the actor's actual
/// content rather than the whole graph. Distinct, non-empty keys joined and
/// byte-capped. Empty when there are no usable keys (the caller then passes
/// `""`, which `get_graph_context` still handles). Pure — unit-tested.
fn reflection_graph_hint(memories: &[(String, serde_json::Value, String)]) -> String {
    // Seed the graph fulltext search from the memory CONTENT (values), not the
    // keys. Entity NAMES (people, projects) live in the values; the graph's
    // fulltext index is over entity names, so keys like `jira_work_context` /
    // `note/1` would almost never match and leave graph-aware reflection inert.
    // We collect distinct alphanumeric word tokens (>= 3 chars) from the values
    // — this both surfaces name-bearing terms AND strips Lucene special chars
    // (`{`, `:`, `"`, …) that a raw-JSON hint could inject into the fulltext
    // query. Bounded in both token count and bytes.
    const MAX_HINT_BYTES: usize = 512;
    const MAX_TOKENS: usize = 60;
    let mut seen = std::collections::HashSet::new();
    let mut parts: Vec<String> = Vec::new();
    let mut total = 0usize;
    'outer: for (_key, value, _t) in memories {
        let text = match value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        for token in text.split(|c: char| !c.is_alphanumeric()) {
            let t = token.trim();
            if t.len() < 3 {
                continue;
            }
            let lower = t.to_lowercase();
            if !seen.insert(lower) {
                continue;
            }
            total += t.len() + 1;
            parts.push(t.to_string());
            if parts.len() >= MAX_TOKENS || total >= MAX_HINT_BYTES {
                break 'outer;
            }
        }
    }
    let mut hint = parts.join(" ");
    if hint.len() > MAX_HINT_BYTES {
        let mut end = MAX_HINT_BYTES;
        while end > 0 && !hint.is_char_boundary(end) {
            end -= 1;
        }
        hint.truncate(end);
    }
    hint
}

/// Best-effort fetch of the actor's current entity graph for graph-aware
/// reflection. Returns `None` when no graph service is configured or the
/// query errors — reflection then proceeds on flat memory only. ACTOR-SCOPED:
/// `get_graph_context` filters every node/edge by `actor_id`.
async fn fetch_reflection_graph_context(
    actor_id: uuid::Uuid,
    memories: &[(String, serde_json::Value, String)],
) -> Option<serde_json::Value> {
    let svc = talos_graph_rag::GRAPH_SERVICE.get()?;
    let hint = reflection_graph_hint(memories);
    // 2 hops / 30 nodes — enough for multi-hop relationship context without an
    // expensive traversal (get_graph_context caps hops≤3, nodes≤50 internally).
    match svc.get_graph_context(actor_id, &hint, 2, 30).await {
        Ok(ctx) => {
            let count = ctx
                .get("entity_count")
                .and_then(|c| c.as_u64())
                .unwrap_or(0);
            if count == 0 {
                None
            } else {
                tracing::debug!(
                    target: "talos_memory_reflection",
                    %actor_id,
                    entity_count = count,
                    "fetched entity-graph context for reflection"
                );
                Some(ctx)
            }
        }
        Err(e) => {
            tracing::debug!(
                target: "talos_memory_reflection",
                %actor_id,
                error = %e,
                "graph context fetch failed; reflecting on flat memory only"
            );
            None
        }
    }
}

/// Upsert reflection-synthesized entities + their relationships into the
/// actor's graph. Best-effort and ACTOR-SCOPED. No-op when no graph service
/// is configured. Every node upsert and edge upsert is independent: one
/// failure logs and continues so a single bad entity can't drop the rest.
async fn persist_synthesized_entities(actor_id: uuid::Uuid, entities: &[SynthesizedEntity]) {
    if entities.is_empty() {
        return;
    }
    let Some(svc) = talos_graph_rag::GRAPH_SERVICE.get() else {
        tracing::debug!(
            target: "talos_memory_reflection",
            %actor_id,
            "no graph service configured; skipping entity synthesis persist"
        );
        return;
    };

    // Bound total work regardless of what the model returned (a max-tokens bump
    // could otherwise let it emit an unbounded entity list).
    const MAX_SYNTH_ENTITIES: usize = 64;
    const MAX_SYNTH_RELS_PER_ENTITY: usize = 16;

    // Resolve a relationship TARGET's node label from the synthesized entity set
    // when the target is itself a named entity — so `Ada —WORKS_ON→ Talos`
    // reuses the typed `Project:Talos` node rather than minting a duplicate
    // `Concept:Talos` (MERGE keys on label+actor_id+name). Falls back to
    // `Concept` for targets not in the set.
    let type_by_name: std::collections::HashMap<&str, &str> = entities
        .iter()
        .take(MAX_SYNTH_ENTITIES)
        .map(|e| (e.name.as_str(), e.entity_type.as_str()))
        .collect();

    let mut nodes_ok = 0usize;
    let mut edges_ok = 0usize;
    for entity in entities.iter().take(MAX_SYNTH_ENTITIES) {
        // Facts → node properties. Numbered keys keep them distinct and within
        // the per-node property cap (sanitizer drops reserved keys / caps count).
        let mut props = serde_json::Map::new();
        for (i, fact) in entity.facts.iter().enumerate() {
            props.insert(format!("fact_{i}"), serde_json::Value::String(fact.clone()));
        }
        match svc
            .upsert_entity(actor_id, &entity.entity_type, &entity.name, props)
            .await
        {
            Ok(()) => nodes_ok += 1,
            Err(e) => tracing::warn!(
                target: "talos_memory_reflection",
                %actor_id,
                error = %e,
                "synthesized-entity node upsert failed (non-fatal)"
            ),
        }

        for rel in entity.relationships.iter().take(MAX_SYNTH_RELS_PER_ENTITY) {
            // Reuse the target's typed node when it's a known synthesized entity;
            // otherwise `Concept` (sanitize_label maps it safely). Subject label
            // is the entity type.
            let object_label = type_by_name
                .get(rel.target.as_str())
                .copied()
                .unwrap_or("Concept");
            match svc
                .upsert_entity_relationship(
                    actor_id,
                    &entity.entity_type,
                    &entity.name,
                    &rel.predicate,
                    object_label,
                    &rel.target,
                )
                .await
            {
                Ok(()) => edges_ok += 1,
                Err(e) => tracing::warn!(
                    target: "talos_memory_reflection",
                    %actor_id,
                    error = %e,
                    "synthesized-entity relationship upsert failed (non-fatal)"
                ),
            }
        }
    }
    tracing::info!(
        target: "talos_memory_reflection",
        %actor_id,
        entities = entities.len(),
        nodes_upserted = nodes_ok,
        edges_upserted = edges_ok,
        "synthesized entities upserted into actor graph (curated graph-write path)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consolidation_schema_matches_output_contract() {
        // The schema's required keys must be exactly the fields parse_summary
        // consumes — a drift here would let the model omit `summary` and still
        // satisfy the constraint.
        let s = consolidation_schema();
        assert_eq!(s["type"], "object");
        let req: Vec<&str> = s["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(req.contains(&"summary"));
        assert!(req.contains(&"key_facts"));
        assert_eq!(s["properties"]["summary"]["type"], "string");
        assert_eq!(s["properties"]["key_facts"]["type"], "array");
    }

    #[test]
    fn reflection_schema_matches_output_contract() {
        // Must mirror the reflection JSON contract INCLUDING the nested entity
        // shape (name/type/facts + relationships[{type,target}]) — the nested
        // constraint is the direct fix for the flaky local-model entity output.
        let s = reflection_schema();
        assert_eq!(s["type"], "object");
        let req: Vec<&str> = s["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        for k in ["insights", "themes", "open_threads", "entities"] {
            assert!(req.contains(&k), "missing required key {k}");
        }
        let ent = &s["properties"]["entities"]["items"];
        assert_eq!(ent["type"], "object");
        let ent_req: Vec<&str> = ent["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(ent_req.contains(&"name"));
        assert!(ent_req.contains(&"type"));
        let rel = &ent["properties"]["relationships"]["items"];
        let rel_req: Vec<&str> = rel["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(rel_req.contains(&"type"));
        assert!(rel_req.contains(&"target"));
    }

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
    fn parse_reflection_recovers_messy_local_model_output() {
        // The real failure a local model produced: the structure survives even
        // when the model fences it, prefixes prose, or double-encodes it — so
        // the synthesized `entities` are NOT lost to the fallback wrap.
        let obj = r#"{"insights":["a"],"entities":[{"name":"Rune","type":"Project"}]}"#;

        // (1) code fence + prose
        let fenced = format!("Here is the reflection:\n```json\n{obj}\n```\nDone.");
        let v = parse_reflection(&fenced);
        assert_eq!(
            v["entities"][0]["name"], "Rune",
            "must recover from a fenced/prose-wrapped object"
        );

        // (2) double-encoded: the object returned as a JSON string.
        let encoded = serde_json::Value::String(obj.to_string()).to_string();
        let v2 = parse_reflection(&encoded);
        assert_eq!(
            v2["entities"][0]["name"], "Rune",
            "must recover a double-encoded object"
        );

        // (3) plain object still works.
        let v3 = parse_reflection(obj);
        assert_eq!(v3["entities"][0]["type"], "Project");
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
        let (s1, u1) = build_reflection_prompt(&memories, None);
        let (s2, u2) = build_reflection_prompt(&memories, None);
        assert_eq!(s1, s2);
        assert_eq!(u1, u2);
        assert!(s1.contains("HIGHER-ORDER INSIGHTS"));
        assert!(s1.contains("open_threads"));
        // Phase 4: the entity-synthesis contract is present in the system prompt.
        assert!(s1.contains("entities"));
        assert!(s1.contains("ENTITY FACTS"));
        assert!(u1.contains("shipped auth refactor"));
        assert!(u1.contains("prefers async reviews"));
        // No graph → entity_graph is null in the user prompt.
        assert!(u1.contains("\"entity_graph\":null"));
    }

    #[test]
    fn reflection_prompt_folds_in_graph_context() {
        let memories = vec![(
            "note/1".to_string(),
            serde_json::json!({"note": "x"}),
            "episodic".to_string(),
        )];
        let graph = serde_json::json!({
            "entities": [{
                "type": "Project", "name": "Talos",
                "relationships": [{"type": "BLOCKED_BY", "target": "SECP-11779", "target_labels": ["Ticket"]}]
            }],
            "entity_count": 1,
            "query": "note/1",
        });
        let (system, user) = build_reflection_prompt(&memories, Some(&graph));
        // Graph context is folded into the user prompt so the LLM can reason
        // over accumulated multi-hop relationships.
        assert!(user.contains("entity_graph"));
        assert!(user.contains("Talos"));
        assert!(user.contains("BLOCKED_BY"));
        // System prompt instructs multi-hop reasoning over the graph.
        assert!(system.contains("multi-hop"));
    }

    #[test]
    fn reflection_prompt_omits_oversized_graph_context() {
        // A pathologically large graph is replaced by a compact marker rather
        // than a truncated (invalid) JSON blob, and never crowds out memories.
        let big_name = "z".repeat(20_000);
        let graph = serde_json::json!({
            "entities": [{"type": "Concept", "name": big_name, "relationships": []}],
            "entity_count": 1,
        });
        let memories = vec![(
            "k".to_string(),
            serde_json::json!({"v": "real memory"}),
            "semantic".to_string(),
        )];
        let (_s, user) = build_reflection_prompt(&memories, Some(&graph));
        assert!(user.contains("entity graph omitted (too large)"));
        assert!(user.contains("real memory"));
    }

    #[test]
    fn parse_reflection_entities_extracts_curated_facts() {
        let v = serde_json::json!({
            "insights": ["..."],
            "entities": [
                {
                    "name": "Ada Lovelace",
                    "type": "Person",
                    "facts": ["leads the platform team", "prefers async reviews"],
                    "relationships": [
                        {"type": "WORKS_ON", "target": "Talos"},
                        {"type": "OWNS", "target": "SECP-11779"}
                    ]
                }
            ]
        });
        let entities = parse_reflection_entities(&v);
        assert_eq!(entities.len(), 1);
        let e = &entities[0];
        assert_eq!(e.name, "Ada Lovelace");
        assert_eq!(e.entity_type, "Person");
        assert_eq!(e.facts.len(), 2);
        assert_eq!(e.relationships.len(), 2);
        assert_eq!(e.relationships[0].predicate, "WORKS_ON");
        assert_eq!(e.relationships[0].target, "Talos");
    }

    #[test]
    fn parse_reflection_entities_is_tolerant() {
        // Missing entities key → empty (never fails reflection).
        assert!(parse_reflection_entities(&serde_json::json!({"insights": []})).is_empty());
        // Non-array entities → empty.
        assert!(parse_reflection_entities(&serde_json::json!({"entities": "nope"})).is_empty());
        // Entry missing name → dropped; malformed relationship → filtered.
        let v = serde_json::json!({
            "entities": [
                {"type": "Concept", "facts": ["orphan"]},
                {"name": "  ", "type": "Person"},
                {"name": "Good", "relationships": [{"type": "", "target": "x"}, {"type": "OWNS", "target": ""}]}
            ]
        });
        let entities = parse_reflection_entities(&v);
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].name, "Good");
        // No `type` field → defaults to Concept.
        assert_eq!(entities[0].entity_type, "Concept");
        assert!(
            entities[0].relationships.is_empty(),
            "empty predicate and empty target relationships are filtered"
        );
    }

    #[test]
    fn reflection_graph_hint_dedups_and_caps() {
        // The hint is derived from memory CONTENT (values), not keys — entity
        // NAMES live in the values and the graph's fulltext index is over names.
        // Keys (`jira_work_context`) must NOT leak into the hint.
        let memories = vec![
            (
                "jira_work_context".to_string(),
                serde_json::json!({ "note": "Rune blocked on Migration. Rune owns Migration." }),
                "semantic".to_string(),
            ),
            (
                "email_triage".to_string(),
                // Lucene special chars in the raw value must be stripped, not
                // injected into the fulltext query.
                serde_json::json!({ "text": "Priya: {reviews} the \"Migration\"" }),
                "episodic".to_string(),
            ),
        ];
        let hint = reflection_graph_hint(&memories);
        let tokens: Vec<&str> = hint.split(' ').collect();
        // Name-bearing content tokens are surfaced...
        assert!(tokens.contains(&"Rune"), "hint: {hint:?}");
        assert!(tokens.contains(&"Priya"), "hint: {hint:?}");
        assert!(tokens.contains(&"Migration"), "hint: {hint:?}");
        // ...deduped (Rune/Migration appear multiple times, once each)...
        assert_eq!(tokens.iter().filter(|t| **t == "Rune").count(), 1);
        assert_eq!(tokens.iter().filter(|t| **t == "Migration").count(), 1);
        // ...and keys never leak in.
        assert!(!hint.contains("jira_work_context"), "hint: {hint:?}");
        assert!(!hint.contains("email_triage"), "hint: {hint:?}");
        // Lucene special chars stripped (no `{`, `}`, `:`, `"`).
        assert!(
            !hint.contains(['{', '}', ':', '"']),
            "hint must not carry Lucene metachars: {hint:?}"
        );
        assert!(reflection_graph_hint(&[]).is_empty());
    }

    #[test]
    fn reflection_prompt_truncates_oversized_input() {
        let big = "x".repeat(100_000);
        let memories = vec![(
            "k".to_string(),
            serde_json::json!({ "v": big }),
            "semantic".to_string(),
        )];
        let (_s, u) = build_reflection_prompt(&memories, None);
        assert!(u.len() <= 24_000);
    }

    #[test]
    fn reflection_key_is_stable_latest() {
        // The single-latest overwrite key must not drift.
        assert_eq!(REFLECTION_KEY, "reflection/latest");
    }
}
