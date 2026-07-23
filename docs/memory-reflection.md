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

## Schema-constrained output (both tiers)

The reflection JSON contract is enforced with **schema-constrained structured
output**, not prompt-and-parse — the reliability fix that makes the well-formed
shape the default rather than the lucky case:

- **Local (tier-1, Ollama):** `OllamaClient::complete_with_schema` passes
  `reflection_schema()` in the Ollama `format` field (Ollama Structured Outputs),
  which shape-constrains the reply — distinct from the old `format:"json"` mode
  that guaranteed valid JSON *syntax* only. Temperature is pinned to `0.1` for
  deterministic structure, and the 4xx-retry path drops `think` while keeping the
  schema.
- **External (tier-2, Anthropic):** `LlmClient::generate_with_schema` uses
  **tool-use** — a single tool whose `input_schema` is `reflection_schema()` with
  `tool_choice` forcing it — and extracts the `tool_use` block's `input`. This
  replaces `generate_text`'s ask-for-JSON-and-strip-fences approach, which could
  still return the wrong shape.

`consolidate` uses the same pair with `consolidation_schema()`. The tolerant
parsers (`coerce_json_object` → `parse_reflection` / `parse_summary`) remain as
belt-and-suspenders for a model that ignores the constraint, but they are no
longer the primary guarantee. Both schema builders live in
`talos-memory-consolidation` and feed **both** structured-output paths from one
definition, so the local and external contracts can never drift apart.

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

## Phase 4 — entity-graph synthesis (graph-write policy + graph-aware reflection)

Phase 4 resolves the prior "graph-RAG grounding layer" gap. It has three parts.

### 1. Graph-write policy — synthetic self-outputs do NOT auto-extract

`talos_memory::spawn_graph_extraction` now takes a `kind: Option<&str>` and
**skips generic auto-extraction when the kind is a synthetic self-output**
(`talos_memory::is_synthetic_memory_kind` / `SYNTHETIC_MEMORY_KINDS`, which
includes `"reflection"`, `daily_brief`, `judge`, `ml_digest`, …). Rationale: the
entity graph is built from **real source memories**, never the assistant's own
inferences — auto-mining reflections/briefs/verdicts into Neo4j would let a
future response ground on entities derived from a prior inference (reflection →
graph → recall → reflection feedback amplification).

The two internal call sites thread the kind through:

- `persist_memory_with_metadata_typed` passes the row's `metadata.kind`
  (`metadata_kind(metadata)`), so a `persist_reflection` write (stamped
  `{"kind":"reflection"}`) no longer auto-extracts.
- `consolidate_memory` passes `Some("consolidated")`. **`"consolidated"` is
  deliberately absent from `SYNTHETIC_MEMORY_KINDS`** — a consolidated summary
  is condensed **real** content, so it STILL auto-extracts. Verified by
  `spawn_graph_extraction_synthetic_kind_tests`.
- The MCP `compress_actor_context` path passes `None` (condensed real memories,
  no synthetic kind) → still extracts.

Reflection-derived entities therefore reach the graph via exactly **one**
deliberate, curated path — the entity synthesis below — instead of noisy
insight-text auto-mining.

### 2. Deliberate entity synthesis — curated first-class graph nodes

The reflection JSON contract gained an `entities` field:

```json
{"insights":[...], "themes":[...], "open_threads":[...],
 "entities":[{"name":"...", "type":"Person|Project|Ticket|Concept|...",
              "facts":["..."],
              "relationships":[{"type":"WORKS_ON|BLOCKED_BY|...","target":"..."}]}]}
```

`parse_reflection_entities` extracts these tolerantly (missing/malformed
`entities` → empty; nameless entries dropped; empty-predicate/target
relationships filtered) so reflection never fails on a model that ignored the
contract. Each synthesized entity is upserted into the actor's graph via two new
`GraphRagService` primitives:

- **`upsert_entity(actor_id, label, name, props)`** — node-only MERGE
  (`build_node_upsert_cypher`, a PURE unit-tested helper):
  `MERGE (n:{label} {actor_id:$actor_id, name:$name}) SET n += $props SET
  n.source_key=$source_key, n.updated_at=$now`. `label` runs through
  `sanitize_label` (allowlist → canonical token or `Concept`); `props` run
  through the same `sanitize_property_key` + reserved-key guard as extraction,
  so a synthesized prop named `actor_id`/`name`/`source_key`/`updated_at` is
  **dropped** — a fact can never hijack the tenant boundary or MERGE identity.
- **`upsert_entity_relationship(...)`** — reuses the batched triple-upsert
  kernel (labels/predicate sanitized, `actor_id`-scoped MERGE) for the edges.

Both stamp `source_key = "reflection_synthesis"` to distinguish curated
reflection entities from auto-extracted ones. Persistence is **best-effort**:
node/edge failures log and continue; the reflection memory write is the primary
output and lands regardless (`persist_synthesized_entities`).

### 3. Graph-aware reflection — multi-hop input

Before building the prompt, `run_reflection_tick` fetches the actor's **current
entity graph** (`GraphRagService::get_graph_context(actor_id, hint, 2, 30)`,
seeded by a hint built from recent memory keys) and folds it into the reflection
user prompt as `entity_graph` context, byte-capped separately
(`MAX_GRAPH_CONTEXT_BYTES`) so it never crowds out the flat memory rows. The
system prompt instructs the model to **reason over accumulated multi-hop
relationships** (Person → owns → Project → blocked-by → …), not just flat rows.
The fetch is best-effort and non-fatal: no graph handle / query error / empty
graph → `None`, and the prompt degrades to flat-memory-only.

### Tier-1 privacy & actor scoping

- **No new external-LLM path.** The `entities` list comes from the reflection
  completion that is **already tier-gated** (`plan_action` — a tier-1 actor's
  synthesis runs on **local Ollama only**). The graph **write** is a Neo4j MERGE
  (no LLM, no external egress), so it needs no additional tier gate. The
  auto-extraction path (`extract_and_store_entities`) remains independently
  tier-gated for real memories.
- **Actor-scoped.** Every graph read (`get_graph_context`) and write
  (`upsert_entity` / `upsert_entity_relationship`) is keyed on `actor_id`
  (`WHERE`/`MERGE ... actor_id=$actor_id`); one actor's entities can never touch
  another's, and the reserved-property guard prevents a synthesized prop from
  rewriting `actor_id`.

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
