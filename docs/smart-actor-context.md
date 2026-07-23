# Smart actor-memory context

Bounded, cleaned, node-scoped `__actor_context__` assembly. **Phase 1** (below)
added the byte budget, kind filter, min-score floor, and node-scoped injection.
**Phase 2** (further down) blends the retrieval layers into one fused
relevance/recency/importance ranking and adds a HyDE toggle.

## Grounding by default (2026-07)

Grounded memory is now the **default**, not opt-in:

- **Assembly** is smart by default — `ENABLE_SMART_MEMORY_CONTEXT` and
  `ENABLE_ADAPTIVE_RANK` (serving) default **ON** (set `=false` to fall back to
  the legacy unranked path). So `__actor_context__` is always ranked, kind-
  filtered, and byte-budgeted; the per-node `needs_memory` gate is therefore
  active by default (only nodes with `needs_memory != false` receive it).
- **Recall** is ranker-backed by default — `ENABLE_RANKED_RECALL` defaults **ON**,
  so the explicit recall path (worker `agent_memory::search`, MCP
  `actor_recall_*`) routes through the same fused ranker.
- **Injection is automatic for actor-bound workflows** (Tier 2): a workflow with
  a bound `actor_id` injects `__actor_context__` **by default** — the direct
  trigger + GraphQL/UI paths (via `ExecutionOrchestrationService::trigger`), the
  scheduler, sub-workflows, and `GmailPush` new-executions. The **binding**
  actor drives it (never the shared user-default actor — that would
  cross-contaminate memory pools); **resumes** (`ApprovalGate`/
  `WorkflowSuspension`) never inject.
  - **Secure default scope = `Curated`** (durable `semantic` + `episodic` only).
    Transient `working` memory is EXCLUDED by default so a short-lived secret
    never lands in an execution trace. An explicit `inject_memory_context=true`
    opts into the `Full` scope (adds `working`). See `MemoryScope`.
  - **Per-workflow opt-out**: a top-level `inject_memory: false` in `graph_json`
    (default true) disables injection for that workflow — versions with it, no
    migration.
  - **Defense in depth**: injected memory is encrypted at rest and DLP-redacted
    (structured secrets) on BOTH the module-input and output copies; tenancy is
    single-actor and the actor is the workflow's own (owner-validated).

## Phase 1

## The problem

On actor-bound runs the controller builds one `__actor_context__` object
per execution and the engine injects it into **every** node's input. The
legacy retriever
(`talos_workflow_repository::WorkflowRepository::get_relevant_actor_context`)
had four issues:

1. **Count-capped, not byte-capped** — capped at ~10 memories. A few large
   values (`ask_thread` / `daily_brief`, 15KB+ each) balloon node inputs to
   ~2M parse-fuel and starve nodes.
2. **No `metadata.kind` filter** — synthetic LLM self-outputs (briefs,
   judge verdicts, digests) are recalled as "sources", amplifying
   hallucinations on every run.
3. **No similarity floor** — semantic recall used `min_score = 0.0`.
4. **Injected everywhere** — even nodes that never read memory get the
   context on their input.

## What Phase 1 changes (flag ON)

Retrieval becomes **kind-filtered, min-score-floored, byte-budgeted**, and
injection becomes **node-scoped**. Same tenancy/crypto invariants: every
recall only ever queries the bound `actor_id`, always through
`talos_memory`'s decrypt-correct, tier-1-embed-gated APIs — no hand-rolled
SQL or decrypt.

### Retriever (`get_relevant_actor_context_smart`)

Three layers, all merged (not early-returned) then deduplicated and packed:

- **Layer 1 — graph RAG** (`GRAPH_SERVICE.get_graph_context`): unchanged;
  entity context is not a synthetic self-output. Bounded by the per-memory
  cap like any other row.
- **Layer 2 — semantic** via
  `talos_memory::recall_semantic_filtered(min_score = FLOOR,
  exclude_kinds = SYNTHETIC_MEMORY_KINDS)`, over-fetching ~3× the count
  budget. The `metadata->>'kind' != ALL($6)` and `>= min_score` predicates
  run at the DB layer (NULL-safe: NULL metadata / missing `kind` passes).
- **Layer 3 — recency** via
  `talos_memory::recall_recent_excluding_types_and_kinds(["scratchpad"],
  SYNTHETIC_MEMORY_KINDS)` — the kind-filtered sibling of the legacy
  recency fallback. Always folded in (the byte budget decides survivors).

Merge/dedup/floor/scratchpad selection is one pure, unit-tested function:
`talos_memory::actor_context::select_candidates`. Order of precedence:
graph → semantic (score-descending) → recency; first occurrence of a key
wins; scratchpad rows dropped in every layer; below-floor semantic hits
dropped (defense-in-depth re-assertion of the SQL floor).

### Byte-budget packer (`pack_within_budget`)

`talos_memory::actor_context::pack_within_budget(actor_id, candidates,
byte_budget, per_memory_cap)`:

1. **Per-memory truncation** — each value is first serialized; if it
   exceeds `per_memory_cap` its serialized form is cut to the largest
   UTF-8 **char boundary** at/under the cap (never mid-codepoint), wrapped
   as a JSON string with the `…[truncated]` marker (`TRUNCATION_MARKER`).
   So one 15KB memory can't dominate the budget.
2. **Budget pack** — walk candidates in relevance order, tentatively add
   each, re-measure the **full** assembled payload (`assemble_payload`
   wrapper included), and drop-and-**stop** at the first row that would
   exceed `byte_budget`. Relevance order is authoritative — we don't skip
   ahead to squeeze a smaller lower-ranked row in, keeping the output
   deterministic. The returned `Vec` fed to `assemble_payload` is
   guaranteed to serialize to `≤ byte_budget` bytes.

### Node-scoped injection

A per-node `needs_memory` graph-json field (**default `true`**, so no
existing graph changes behaviour) declares whether a node consumes
`__actor_context__`. It round-trips as part of the node `data` that the
engine stores in `node_configs`, read at dispatch via
`ParallelWorkflowEngine::node_needs_memory`. The two dispatch sites
(`engine_dispatch_single`, `engine_dispatch_pipeline` — keyed on the
chain head) gate the insert through the pure
`reserved_keys::should_inject_actor_context(smart_enabled, needs_memory)`:

- **flag OFF** → always inject (ignore `needs_memory`) — byte-identical to today.
- **flag ON** → inject only where `needs_memory == true`.

## Flag + knobs (`talos-config`)

| Resolver | Env var | Default |
|---|---|---|
| `smart_memory_context_enabled()` | `ENABLE_SMART_MEMORY_CONTEXT` | `false` |
| `smart_memory_context_byte_budget()` | `SMART_MEMORY_CONTEXT_BYTE_BUDGET` | `12_000` bytes |
| `smart_memory_context_per_memory_cap()` | `SMART_MEMORY_CONTEXT_PER_MEMORY_CAP` | `3_000` bytes |
| `smart_memory_context_min_score()` | `SMART_MEMORY_CONTEXT_MIN_SCORE` | `0.25` (clamped `[0,1]`) |

Truthy tokens for the flag: `true | 1 | yes | on` (case-insensitive). The
numeric knobs use `positive_env_or_default` — `=0`/negative collapse to the
default (destructive-zero guard).

## Synthetic-kinds source of truth

`talos_memory::SYNTHETIC_MEMORY_KINDS` (+ `synthetic_memory_kinds()` owned
`Vec<String>`): `recall, meeting_prep, daily_brief, ask_thread, synthesize,
judge, inline_judge, ensemble, llm_dispatch, capability_dispatch, ml_digest,
commitment_check`. One list, used by every reader; conservative by design —
only SELF-OUTPUT kinds, never human-sourced memories (a human note wrongly
excluded is worse than a synthetic note wrongly included).

## Preserved tenancy invariants

- Every recall passes exactly the bound `actor_id`; the predicate is never
  widened. All SQL is `WHERE actor_id = $1`-scoped.
- No hand-rolled SQL/decrypt — retrieval goes through `talos_memory`'s
  decrypt-correct path (per-row AAD, v0–v4 format dispatch) and honours the
  tier-1 embed gate inside `recall_semantic_filtered`.
- The kind filter only ever *removes* rows; it can never surface another
  actor's data.

## Rollout

1. **Dark** — deploy with `ENABLE_SMART_MEMORY_CONTEXT` unset (default).
   Zero behaviour change (byte-identical assembly + inject-everywhere).
2. **Validate** — flip the flag in a dev/canary env. Compare injected
   `__actor_context__` sizes (`approx_token_count`) and spot-check that
   synthetic kinds no longer appear in grounding context.
3. **Flip** — enable in production. Tune `SMART_MEMORY_CONTEXT_*` knobs as
   needed. Phase 2 can then opt individual nodes out via `needs_memory`
   and refine the synthetic-kinds list.

---

# Phase 2 — fused multi-signal ranking + HyDE

Phase 1 packed the merged candidates in **raw retrieval order** (graph →
semantic-by-cosine → recency) and used the three layers as fallback tiers.
Phase 2 blends the layers into **one ranked set** scored by relevance +
recency + importance, then packs in **fused-score order**. Everything stays
behind the SAME `ENABLE_SMART_MEMORY_CONTEXT` flag: OFF ⇒ byte-identical to
today (the legacy non-smart path is untouched); only the smart branch's
ordering changes. The byte-budget packer (`pack_within_budget`) and its
`≤ byte_budget` guarantee are reused verbatim — Phase 2 only changes the
ORDER of the rows fed into it.

## Signals preserved through the pipeline

The smart retriever no longer collapses each layer to `(key, value, type)`
immediately. `select_candidates` now emits a `Candidate` per row carrying
the ranking signals:

| field | semantic hit | graph context | recency row |
|---|---|---|---|
| `relevance` | `MemoryHit.score` (cosine) | `SMART_MEMORY_CONTEXT_GRAPH_BASELINE` (0.6) | `SMART_MEMORY_CONTEXT_RECENCY_BASELINE` (0.4) |
| `updated_at` | `MemoryHit.updated_at` | `None` (neutral recency) | row `updated_at` |
| `importance_hint` | `metadata.importance` if numeric | `None` | `None` |

The recency layer needs `updated_at`, so Layer 3 calls the new
`talos_memory::recall_recent_excluding_types_and_kinds_ts` — a sibling of the
Phase-1 recency fn with an **identical** decrypt column set, AAD path, and
`metadata.kind` filter, adding only the projected `updated_at` column and a
wider return tuple (`updated_at` is read as `Option<DateTime<Utc>>` per
structural-lint check 52, so schema drift errors rather than silently
defaulting). `select_candidates` dedups by key **keeping the highest-relevance
instance** (a strong semantic hit beats the same key's recency baseline).

## Fused score

`talos_memory::actor_context::fused_score(candidate, weights, now)`:

```text
fused = W_RELEVANCE  * relevance
      + W_RECENCY    * recency_decay(now - updated_at)     [NEUTRAL_RECENCY (0.5) if no updated_at]
      + W_IMPORTANCE * importance(memory_type, importance_hint)
```

- **`recency_decay(age)` = `0.5^(age_days / RECENCY_HALFLIFE_DAYS)`** —
  exponential half-life. A brand-new memory scores 1.0; one half-life old
  scores 0.5; each further half-life halves it. Future timestamps clamp to
  1.0; a degenerate (`≤0`) half-life falls back to `NEUTRAL_RECENCY` rather
  than dividing by zero. A candidate with **no** `updated_at` gets
  `NEUTRAL_RECENCY = 0.5` — a missing timestamp never zeroes a candidate out.
- **`importance(c)`** — a per-`memory_type` base blended 50/50 with the
  clamped `importance_hint` when present:

  | memory_type | base |
  |---|---|
  | `semantic` (durable facts / persona) | 1.0 |
  | `episodic` (events) | 0.66 |
  | `working` (short-lived scratch) | 0.33 |
  | `scratchpad` | 0.0 (filtered upstream) |
  | unknown | 0.5 (neutral) |

  With a hint: `importance = (base + clamp(hint, 0, 1)) / 2`. Both the
  structural signal (what KIND of memory it is) and the writer's explicit
  `metadata.importance` contribute.

`now` is **injected**, never read from the clock inside the scorer — the
production path passes `chrono::Utc::now()` once; tests/eval pass a fixed
`now` for determinism. `rank_candidates` sorts by `fused_score` DESC (stable),
tie-breaking on raw `relevance` then `updated_at` (newer first), and the
sorted rows are flattened and handed to `pack_within_budget` unchanged.

## HyDE toggle

`ENABLE_SMART_MEMORY_HYDE` (`smart_memory_hyde_enabled()`, default OFF). When
ON, the semantic layer embeds a HyDE (Hypothetical Document Embeddings)
rewrite of the hint (`SearchMethod::HyDE` — "An answer to the question '…'
would be: ") instead of the raw hint (`SearchMethod::Direct`). The smart path
routes through `recall_semantic_filtered` with the toggled method (NOT the
`recall_hyde` wrapper) precisely so the `min_score` floor AND the
`exclude_kinds` synthetic-kind filter are preserved under HyDE. HyDE still
embeds, so the **tier-1 local-only embed gate** inside
`recall_semantic_filtered` applies unchanged.

## Phase-2 knobs (`talos-config`)

| Resolver | Env var | Default |
|---|---|---|
| `smart_memory_context_w_relevance()` | `SMART_MEMORY_CONTEXT_W_RELEVANCE` | `1.0` |
| `smart_memory_context_w_recency()` | `SMART_MEMORY_CONTEXT_W_RECENCY` | `0.3` |
| `smart_memory_context_w_importance()` | `SMART_MEMORY_CONTEXT_W_IMPORTANCE` | `0.5` |
| `smart_memory_context_recency_halflife_days()` | `SMART_MEMORY_CONTEXT_RECENCY_HALFLIFE_DAYS` | `7.0` |
| `smart_memory_context_graph_baseline()` | `SMART_MEMORY_CONTEXT_GRAPH_BASELINE` | `0.6` (clamped `[0,1]`) |
| `smart_memory_context_recency_baseline()` | `SMART_MEMORY_CONTEXT_RECENCY_BASELINE` | `0.4` (clamped `[0,1]`) |
| `smart_memory_hyde_enabled()` | `ENABLE_SMART_MEMORY_HYDE` | `false` |

The weights use `positive_env_or_default` — `=0`/negative collapses to the
default + WARN (a `0` weight would silently drop a whole signal; use a small
positive like `0.01` to de-weight intentionally). The half-life uses the same
guard (a `0` would divide-by-zero). Baselines are clamped into `[0,1]`.

## Retrieval-quality eval

`eval_fused_beats_single_signal_baselines` (in `talos-memory`, `#[cfg(test)]`,
network-free) is the "measure smarter" deliverable. It builds a fixture of
16 synthetic `Candidate`s with KNOWN relevance / age / importance and a
labeled "useful" set of 5:

- an **old but highly-relevant fact** (relevance-only recovers it, recency-only
  misses it),
- two **recent + flagged-important notes** that relevance-alone under-ranks,
- a **strong recent hit** and a **mid-relevance recent+important** one.

Distractors are either **stale-but-relevant** (relevance-only false positives)
or **recent-but-irrelevant** (recency-only false positives). The eval scores
the fixture three ways — **fused** (default weights), **relevance-only**
(`W_RECENCY = W_IMPORTANCE = 0`), **recency-only** (`W_RELEVANCE =
W_IMPORTANCE = 0`) — and asserts, against the labels:

- **recall@5** — fused recovers the full useful set (`1.0`) and **strictly
  beats** both baselines (relevance-only `0.4`, recency-only `0.4`).
- **MRR** — fused ranks a useful item first (`1.0`) and **strictly beats**
  both baselines (relevance-only `0.5`, recency-only `≈0.33`).

A second test (`eval_weight_change_moves_ranking_expected_direction`) asserts
that **raising `W_RECENCY` never demotes** the recent-critical note and never
promotes a stale item — i.e. the weights move the ranking in the expected
direction. The eval is pure: fixtures are scored directly via `fused_score` /
`rank_candidates` with an injected `now`; no embeddings or DB. This proves the
fusion improves ORDERING, not just the Phase-1 byte bound.

## Phase 3a — durable memory signals

Phases 1+2 rank from signals computed at retrieval time (cosine relevance,
`updated_at`, `metadata.importance`). Phase 3a adds three **durable** columns to
`actor_memory` that accrue over a memory's life and feed the SAME fused ranker,
plus the substrate for Phase 3b consolidation.

### New columns (`migrations/20260722000000_actor_memory_signal_columns.sql`)

| Column | Type | Notes |
|---|---|---|
| `importance` | `real` NULLable | Write-time importance score in `[0,1]`. `NULL` = "not yet scored" (rows written before this migration) — the ranker treats `NULL` as an absent hint. No NOT NULL default (a synthetic default is indistinguishable from a real score). |
| `access_count` | `integer NOT NULL DEFAULT 0` | Times this row was packed into an injected `__actor_context__` set. |
| `last_accessed_at` | `timestamptz` NULLable | Most-recent injection time; substrate for the Phase 3b cold-memory scan. |

Index `idx_actor_memory_signals (actor_id, importance, last_accessed_at)`
supports Phase 3b's "stale + low-importance" candidate scan. The migration is
idempotent (`ADD COLUMN IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`), no
`CONCURRENTLY`. The `value_enc`/`value_key_id`/`value_format` decrypt path is
untouched — these are additive plaintext SIGNAL columns only.

### Write-time importance scoring

`talos_memory::persist_memory_with_metadata_typed` computes
`actor_context::write_time_importance(memory_type, metadata)` on every write and
binds it into `importance` (INSERT + `ON CONFLICT DO UPDATE SET importance =
EXCLUDED.importance` — re-scored on overwrite). The score is the memory-type
base (`importance_base`) blended 50/50 with a numeric `metadata.importance` when
present, else the bare base — the SAME semantics `importance()` uses for its
hint, in ONE shared `pub fn` so the write path and the ranker can never drift.
It is written **regardless of the `ENABLE_SMART_MEMORY_CONTEXT` flag** (a
harmless dormant column that accrues for when the flag is on and for 3b).
`access_count` / `last_accessed_at` are deliberately NOT reset on a content
update — access history persists across overwrites.

### Non-blocking access tracking

After the smart path (`get_relevant_actor_context_smart`) packs its final set,
it bumps the durable access signal for exactly those rows via
`talos_memory::bump_access(pool, actor_id, keys)` — ONE batched
`UPDATE … SET access_count = access_count + 1, last_accessed_at = now()
WHERE actor_id = $1 AND key = ANY($2)` per context injection. This is the
first-ever recall-path mutation, so it runs **fire-and-forget** in a
`tokio::spawn` (best-effort, logged at debug on error, never propagated) — it
adds zero latency to context assembly. It fires **only on the flag-ON smart
path**; with the flag off, no bump occurs. The SQL lives in `talos-memory`
(never inline in the repository crate — lint check 1). `bump_access` does not
touch `updated_at` (an access is a read, not a content write — recency-decay
tracks writes) or `importance`.

### Durable signals into the fused ranker

The recall functions the smart path uses (`recall_semantic_filtered` and
`recall_recent_excluding_types_and_kinds_ts`) now project `importance` +
`access_count`, read as `Option` with fail-loud drift semantics
(`try_get::<Option<f32/i32>, _>("col")?` — checks 52/55; widened to the ranker's
`f64`/`i64`). `MemoryHit` gained `importance: Option<f64>` + `access_count:
Option<i64>`. In `select_candidates`:

- `Candidate.importance_final` ← the durable `importance` column when present.
  This is a **final** write-time score (already base⊕`metadata.importance`
  blended at persist time), so the ranker uses it **directly** — no second base
  blend. This matters because Phase 3b consolidation writes explicit importance
  values; a re-blend would attenuate them back toward the type base.
- `Candidate.importance_hint` ← the legacy `metadata.importance` **only** for
  pre-3a rows (durable column NULL). A raw override that `importance()` blends
  50/50 with the type base — the exact Phase 2 behavior, preserved.
- The two are mutually exclusive per candidate: durable column set ⇒
  `importance_final`; else the metadata fallback ⇒ `importance_hint`. Precedence
  is `importance_final` > `importance_hint` > bare base.
- `Candidate.access_boost` ← `access_boost(access_count)` =
  `1 - 1/(1 + count)` — a saturating curve in `[0,1)` (0 accesses → `0.0`
  neutral; diminishing returns as it grows). `None` (older rows / no signal) is
  neutral.

The access signal folds **into the importance term** rather than adding a
fourth fused term — `fused_score` stays 3-term (relevance + recency +
importance), avoiding Weights/knob churn:

```text
base_importance = importance_final.clamp(0,1)                     [durable column — used directly]
                | (importance_base(type) + hint.clamp(0,1)) / 2   [pre-3a metadata fallback — blended]
                | importance_base(type)                           [bare base, no signal]
importance(c)   = clamp01( base_importance + access_weight * access_boost )   [base_importance if no boost]
fused_score(c)  = W_RELEVANCE  * relevance
                + W_RECENCY    * recency_decay(now - updated_at)
                + W_IMPORTANCE * importance(c)
```

The nudge is **additive and clamped**, so access frequency only ever raises
importance and the result stays in `[0,1]`; when `access_boost` is `None` the
result is exactly the base/hint blend (flag-off and pre-3a parity). The function
stays total/pure/NaN-safe (non-finite weight or boost degrades to a zero nudge).

### New config knob

| Function | Env var | Default |
|---|---|---|
| `smart_memory_context_access_weight()` | `SMART_MEMORY_CONTEXT_ACCESS_WEIGHT` | `0.15` |

`positive_env_or_default` + clamp to `[0,1]`: `=0`/negative/unparseable
collapses to the default (a `0` would silently disable the whole access signal),
values above `1.0` clamp. Small by default so access frequency refines but never
dominates base/hint importance. Wired through `docker-compose.yml`'s controller
`environment:` alongside the other `SMART_MEMORY_CONTEXT_*` passthroughs.

---

## Phase 3b — autonomous consolidation

A **default-OFF** background loop (`talos-memory-consolidation`) that summarizes
an actor's long-tail memories via a **tier-gated LLM** and consolidates them:
persist ONE durable semantic summary and delete the source episodic rows, all in
one committed transaction. Wired in `controller/src/main.rs` next to the
teacher-audit scheduler; `spawn_memory_consolidation_scheduler` returns without
spawning a task when the loop is disabled (zero background overhead).

### The tier gate (fail-closed, tier-1 local-only)

The #1 invariant: a **tier-1 actor** (`actors.max_llm_tier = 'tier1'`) has
privacy-sensitive memory that **MUST NEVER reach an external LLM provider**. Its
summary is generated on a **local Ollama model ONLY**, or **skipped entirely**.

The decision is the **shared** `ActorRepository::resolve_llm_tier_decision`
(the same fail-closed matrix graph-RAG's entity extraction uses — one
implementation, no drift), returning `{External, LocalOnly, Skip}`:

| Actor tier | Condition | Decision | LLM used |
|---|---|---|---|
| `tier2` | — | `External` | Anthropic (external) allowed |
| `tier1` | `tier1_local_ok` attested **and** Ollama wired | `LocalOnly` | local Ollama only |
| `tier1` | otherwise | `Skip` | none |
| missing actor / DB error / unknown tier | — | `Skip` | none |

`tier1_local_ok` is an operator attestation (`MEMORY_CONSOLIDATION_TIER1_LOCAL_OK`,
default **false**) that `OLLAMA_URL` points at an on-host model. Fail-closed: a
missing actor, a DB error, or an unknown tier all **Skip** — the content never
reaches any LLM. In code, the external `LlmClient` is constructed **only** on the
`SummarizeExternal` routing branch (`plan_action`), so a `LocalOnly`/`Skip`
actor's content can never touch Anthropic even by accident.

### The candidate scan

`talos_memory::scan_consolidation_candidates` (SQL lives in `talos-memory`, per
lint 1) selects an actor's **episodic** rows that are **old**, **cold**, and
**low- or unscored-importance**:

```sql
WHERE actor_id = $1
  AND memory_type = 'episodic'
  AND (expires_at IS NULL OR expires_at > now())
  AND updated_at < now() - make_interval(days => $2::int)   -- min age (lint 27 cast)
  AND (importance IS NULL OR importance < $3)               -- low / unscored
ORDER BY importance ASC NULLS FIRST,
         last_accessed_at ASC NULLS FIRST,
         updated_at ASC                                     -- coldest, least-important, oldest first
LIMIT $4
```

`NULLS FIRST` is deliberate: Phase-3a leaves older rows' `importance` and
`last_accessed_at` NULL, and those **unscored + never-re-accessed** rows are
exactly the prime consolidation candidates (this resolves the Phase-3a
NULL-ordering note). Semantic / working / scratchpad memory and recent or
high-importance rows are **never** touched. `min_age_days` is floored at **1**
in the scan (`(round() as i32).max(1)`) so even a misconfigured sub-1-day
setting always leaves a full day of headroom — recent memory can never be
consolidated.

### Fair fleet rotation

The per-tick scan is bounded (`max_actors_per_tick`), so `scan_actors_for_
consolidation` orders active actors by **`last_consolidated_at ASC NULLS FIRST`**
(a least-recently-swept cursor; migration `20260722010000`) and the loop stamps
every actor it examined — consolidated, tier-gate-skipped, or no-candidates —
via `mark_actors_consolidated`. Without the cursor an `ORDER BY id` scan would
revisit the same lowest-id actors each tick and starve the rest once the fleet
exceeds the per-tick cap. The tier decision is resolved from the `max_llm_tier`
already carried on the scanned row (`llm_tier_decision_from_tier_str`, sharing
the same pure fail-closed matrix as graph-RAG's async path) — no per-actor tier
lookup.

### The atomic persist + forget

`talos_memory::consolidate_memory` is the single kernel shared by the MCP
`consolidate_actor_memory` handler and this loop. In one transaction it persists
the summary as a `"semantic"` memory (stamped `metadata.kind = "consolidated"`)
and hard-deletes the source keys, then commits. Graph-RAG entity extraction fires
**post-commit** only (a rolled-back tx must not corrupt the graph). Any LLM
failure or parse failure ⇒ **zero mutation** (the sources stay intact).

Consolidated summaries are **recalled**, not filtered: `"consolidated"` is
deliberately **NOT** in `SYNTHETIC_MEMORY_KINDS` — a consolidated summary
represents real past content that it replaces, so it should surface in recall
(unlike fresh synthetic self-inferences, which are excluded to avoid feedback
amplification).

### Config knobs

| Function | Env var | Default | Notes |
|---|---|---|---|
| `memory_consolidation_enabled()` | `ENABLE_MEMORY_CONSOLIDATION` | `true` | master switch (default ON, Tier 3); scheduler not spawned when off |
| `memory_consolidation_tier1_local_ok()` | `MEMORY_CONSOLIDATION_TIER1_LOCAL_OK` | `false` | operator attestation OLLAMA_URL is on-host |
| `memory_consolidation_interval_secs()` | `MEMORY_CONSOLIDATION_INTERVAL_SECS` | `86400` | tick cadence (daily; only touches the 30-day cold tail) |
| `memory_consolidation_min_age_days()` | `MEMORY_CONSOLIDATION_MIN_AGE_DAYS` | `30.0` | only rows older than this |
| `memory_consolidation_max_importance()` | `MEMORY_CONSOLIDATION_MAX_IMPORTANCE` | `0.4` | clamp `[0,1]`; only low-importance rows |
| `memory_consolidation_batch_size()` | `MEMORY_CONSOLIDATION_BATCH_SIZE` | `20` | clamp `[3,100]`; floor 3 skips trivial clusters |
| `memory_consolidation_max_actors_per_tick()` | `MEMORY_CONSOLIDATION_MAX_ACTORS_PER_TICK` | `25` | clamp `[1,500]` |
| `memory_consolidation_model()` | `MEMORY_CONSOLIDATION_MODEL` | `qwen2.5:7b` | local Ollama model for the tier-1 path |

All numeric knobs route through `positive_env_or_default` (destructive-zero
guard) and are wired through `docker-compose.yml`'s controller `environment:`.

# Tier 3 — self-maintaining memory (learning loops default-ON, 2026-07)

The grounding path (Tier 1) and universal injection (Tier 2) made grounded
memory the default everywhere it's *read*. Tier 3 flips the four **learning
loops** that make that memory *improve itself* from opt-in to default-ON, so the
system gets better with use without any operator action:

| Loop | Flag (now default `true`) | What it does | Why safe to default-on |
|---|---|---|---|
| Rank provenance | `ENABLE_MEMORY_RANK_PROVENANCE` | records execution→memory→outcome signal (keys + numeric features, **never values**) | fire-and-forget, batched single-INSERT, tenant-scoped, retention-swept |
| Rank training | `ENABLE_ADAPTIVE_RANK_TRAINING` | CPU-only per-actor weight fit from that signal | no LLM/egress; cold-start fail-closed to global weights; weights clamped so ranking can't invert |
| Reflection | `ENABLE_MEMORY_REFLECTION` | daily higher-order insight synthesis → one `reflection/latest` semantic memory | input scan **excludes its own kind** → cannot amplify; non-destructive write |
| Consolidation | `ENABLE_MEMORY_CONSOLIDATION` | daily condense of the 30-day cold episodic tail → one semantic summary, sources retired | convergent (monotone-reducing), not amplifying |

## Local-first routing (privacy default for the LLM loops)

Reflection and consolidation call an LLM. Their routing is **local-first**: the
loop-specific `plan_action` prefers the **on-host Ollama model for ALL tiers**
whenever it's reachable — so a tier-2 actor's memory content (including work/CRM
data) **never egresses during background maintenance**. The external provider is
a *fallback* used only when no local model is available, and that fallback is
itself **budget-gated** (skipped when the actor is over its
`max_llm_tokens_per_day`). This is strictly more private than the actor's tier
ceiling requires: a tier-2 ceiling *allows* external but does not *mandate* it.

The shared fail-closed `decide_llm_tier` matrix (also used by graph-RAG) is
deliberately **unchanged** — local-first lives only in the memory loops'
`plan_action`. Tier-1 stays doubly fail-safe: a tier-1 actor is `Skip`ped
entirely unless the operator separately attests on-host Ollama via
`MEMORY_{REFLECTION,CONSOLIDATION}_TIER1_LOCAL_OK` (default `false`).

Routing matrix for the loops:

| Actor tier | Ollama reachable | Attestation | Action | LLM used |
|---|---|---|---|---|
| `tier2` | yes | — | `SummarizeLocal` | local Ollama (**no egress**) |
| `tier2` | no | — | `SummarizeExternal` | external (budget-gated fallback) |
| `tier1` | yes | attested | `SummarizeLocal` | local Ollama |
| `tier1` | yes | not attested | `Skip` | none |
| `tier1` | no | — | `Skip` | none |

## Self-amplification: closed by construction

The one thing that makes memory-write loops dangerous — an LLM citing its own
prior output as "source" so hallucinations compound each run — is closed
unconditionally: reflection's input scan filters `SYNTHETIC_MEMORY_KINDS` at the
DB layer (so it can never reflect on its own `reflection/latest`), and the
default injection path (`get_relevant_actor_context_smart`) excludes the same
kinds at every layer. The legacy (`ENABLE_SMART_MEMORY_CONTEXT=false`) recall
path now also excludes synthetic kinds in both its semantic and recency layers
(defense-in-depth), so reflections can't leak into general context there either.
Consolidation is convergent by construction (it reads `episodic`, writes
`semantic`, and deletes its sources), so it cannot amplify.

## Rollout note

Provenance and training pair as a producer→consumer: training only produces
learned weights once provenance has accrued ≥ `ADAPTIVE_RANK_MIN_EXAMPLES`
labeled examples for an actor. Flipping both on together is safe — serving stays
on global weights during the warm-up window — but learned per-actor ranking only
kicks in after the corpus matures.
