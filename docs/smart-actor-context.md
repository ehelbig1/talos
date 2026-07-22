# Smart actor-memory context

Bounded, cleaned, node-scoped `__actor_context__` assembly — behind a
default-OFF flag. When the flag is OFF the behaviour is **byte-identical**
to the legacy path. **Phase 1** (below) added the byte budget, kind filter,
min-score floor, and node-scoped injection. **Phase 2** (further down) blends
the retrieval layers into one fused relevance/recency/importance ranking and
adds a HyDE toggle.

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
