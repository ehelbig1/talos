# Smart actor-memory context (Phase 1)

Bounded, cleaned, node-scoped `__actor_context__` assembly — behind a
default-OFF flag. When the flag is OFF the behaviour is **byte-identical**
to the legacy path.

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
