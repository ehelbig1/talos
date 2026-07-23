# Autonomous memory reflection (Phase 3)

A scheduled, per-actor background loop that reads across an actor's meaningful
memories and uses a **tier-gated LLM** to synthesize **higher-order insights** —
recurring themes, evolving priorities/goals, relationships between people and
projects, and open threads — then writes them back as ONE new
`reflection`-kind semantic memory.

Reflection **augments**; it does not retire. Contrast with
[consolidation](./smart-actor-context.md) (Phase 3b), which atomically forgets
its source rows after summarizing them: reflection writes one new memory and
**deletes nothing**.

Lives in `talos-memory-consolidation` alongside consolidation, reusing its tier
gate, prompt-cap shape, and scheduler skeleton verbatim.

## Default-OFF

The scheduler is not even spawned unless `ENABLE_MEMORY_REFLECTION` is set. With
the flag off, behavior is byte-identical to before this feature — zero
background overhead, zero new writes.

## What it reads

`talos_memory::scan_reflection_input(pool, actor_id, exclude_kinds, limit)`:

- `memory_type IN ('semantic', 'episodic')` — the meaningful substrate.
  `scratchpad`/`working` memories are ephemeral bookkeeping and are excluded.
- Excludes every synthetic kind in `talos_memory::SYNTHETIC_MEMORY_KINDS`
  (passed as `synthetic_memory_kinds()`), which now **includes `"reflection"`**,
  via the NULL-safe `metadata->>'kind' != ALL($N)` predicate. Excluding
  `"reflection"` is essential: **reflecting on prior reflections would drift**
  and amplify the model's own inferences.
- Only live rows (`expires_at IS NULL OR expires_at > now()`).
- `ORDER BY updated_at DESC` (most recent context first), `LIMIT` =
  `MEMORY_REFLECTION_INPUT_CAP`.
- Actor-scoped (`WHERE actor_id = $1`), fail-loud reads, decrypted through the
  canonical AAD-aware `decrypt_row_value` path.

If an actor holds fewer than `MEMORY_REFLECTION_MIN_MEMORIES` meaningful
memories, it is skipped (no LLM, no write) — there is too little to synthesize.

## The tier gate (tier-1 stays local)

Reflection reuses consolidation's tier gate **verbatim**:
`talos_actor_repository::llm_tier_decision_from_tier_str(&max_llm_tier,
tier1_local_ok, ollama_available)` → `plan_action(...)` →
`PlannedAction::{Skip, SummarizeLocal, SummarizeExternal}`.

- **tier-2** actor → `External`: any configured provider is allowed.
- **tier-1** actor → `LocalOnly` ONLY when the operator has attested locality
  (`MEMORY_REFLECTION_TIER1_LOCAL_OK=true`) AND Ollama is wired; otherwise
  `Skip`. A tier-1 actor's private memory is reflected on the **local Ollama
  model only, or not at all** — it never reaches an external provider.
- Unknown/missing/corrupt tier → `Tier1` (fail closed via
  `LlmTier::from_db_str`), so it can never yield `External`.

The external `LlmClient` (`LlmClient::with_vault(...)`) is constructed **only**
on the `SummarizeExternal` branch — never for a `LocalOnly` or `Skip` actor.
The tier-1 attestation is a **separate** env var from consolidation's
(`MEMORY_REFLECTION_TIER1_LOCAL_OK` vs `MEMORY_CONSOLIDATION_TIER1_LOCAL_OK`) so
the two loops are controlled independently.

## The non-destructive write

`talos_memory::persist_reflection(pool, actor_id, "reflection/latest", value,
metadata)`:

- Writes a `semantic` memory (semantic ignores TTL, so it's durable) via the
  canonical always-encrypt path — per-org DEK, AES-GCM AAD bound to
  `(actor_id, key)`. It is real actor memory.
- Key is `reflection/latest` — the single current reflection per actor is
  **overwritten** each cycle (the `ON CONFLICT (actor_id, key)` upsert refreshes
  it) so reflections never accumulate unboundedly (mirrors `daily_brief/latest`).
- `metadata = {"kind": "reflection", "source_count": N, "reflected_at": <ts>}`.
- **Deletes nothing.** No source is retired.

## Self-grounding guard

`"reflection"` is a member of `talos_memory::SYNTHETIC_MEMORY_KINDS`, so
reflections are **excluded from the smart-actor-context grounding recall** — the
LLM never grounds its responses on its own prior inferences
(feedback-amplification guard). Reflections remain accessible via **explicit**
`actor_recall` / `actor_recall_semantic` (those APIs do not apply the synthetic
exclusion).

By design, reflections are **not auto-injected** into grounding context.
Deliberately feeding reflections into response context is a controlled
follow-up, not part of this phase.

### Known gap — the graph-RAG grounding layer

The kind-filter guard covers the **semantic + recency** layers of
`get_relevant_actor_context_smart`. It does NOT cover **Layer 1 (graph RAG)**:
`persist_reflection` writes a normal semantic memory, so — like `daily_brief`,
`meeting_prep`, and every other synthetic kind — it fires `spawn_graph_extraction`,
seeding Neo4j with entities derived from the reflection's insight text. Graph
entities don't carry the source memory's `metadata.kind`, so reflection-derived
entities remain eligible for the graph grounding layer. The exposure is mild
(the reflection loop's own input scan reads `actor_memory` directly, never the
graph, so the loop itself can't re-ingest its output — no self-drift), it's
**pre-existing platform behavior shared by all synthetic kinds** (not introduced
here), and tier-1 privacy is intact (graph extraction is independently
tier-gated). Phase 4 (entity-graph synthesis) owns the deliberate decision of
what synthesized memory should and shouldn't enter the entity graph — including
whether reflections should graph-extract at all.

## Fair rotation

Reflection uses its own least-recently-swept cursor column
`actors.last_reflected_at` (migration
`20260722050000_actors_last_reflected_at.sql`), distinct from consolidation's
`last_consolidated_at`. `ActorRepository::scan_actors_for_reflection` orders by
`last_reflected_at ASC NULLS FIRST, id`; `mark_actors_reflected` stamps every
actor the tick examined (reflected OR skipped) so the sweep advances through the
whole fleet fairly rather than starving higher-id actors past the per-tick cap.

## Configuration

| Env var | Default | Notes |
|---|---|---|
| `ENABLE_MEMORY_REFLECTION` | `false` | Master switch; scheduler not spawned when unset |
| `MEMORY_REFLECTION_TIER1_LOCAL_OK` | `false` | Operator attestation that Ollama is on-host (tier-1 local reflection) |
| `MEMORY_REFLECTION_INTERVAL_SECS` | `86400` | Daily cadence (slower than consolidation) |
| `MEMORY_REFLECTION_INPUT_CAP` | `40` | Max memories fed to the LLM; clamp `[5, 200]` |
| `MEMORY_REFLECTION_MIN_MEMORIES` | `8` | Floor to reflect at all; clamp `[3, 100]` |
| `MEMORY_REFLECTION_MAX_ACTORS_PER_TICK` | `25` | Fleet fan-out per tick; clamp `[1, 500]` |
| `MEMORY_REFLECTION_MODEL` | `qwen2.5:7b` | Ollama model for the tier-1 local path |
