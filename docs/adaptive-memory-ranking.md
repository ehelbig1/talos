# Adaptive per-actor memory ranking

The smart-context retriever (`get_relevant_actor_context_smart`) ranks an
actor's memories by a fixed, hand-tuned fused score (relevance + recency-decay +
importance, weighted by `SMART_MEMORY_CONTEXT_W_*`). The weights are global —
they don't adapt to whether a given actor's memories actually led to good
execution outcomes.

**Adaptive memory ranking** is the multi-phase effort to LEARN a per-actor
ranking from outcome signals. This document describes **Phase 1: the provenance
foundation** — the observe-only substrate that records what was ranked so a
later phase can learn from it. Phase 1 changes NO ranking behaviour.

## Phase 1 — provenance (this phase)

### What it records

For each actor-bound execution that injected `__actor_context__` on the smart
path, Phase 1 records — for every memory that survived into the packed
(injected) set — a row in `execution_memory_context`:

| column         | meaning                                                        |
| -------------- | -------------------------------------------------------------- |
| `execution_id` | the execution this context was packed for                     |
| `actor_id`     | the owning actor (tenancy)                                     |
| `memory_key`   | the `actor_memory` key (NOT the value)                        |
| `relevance`    | cosine/baseline relevance signal                              |
| `recency`      | `recency_component` in `[0,1]` (exp decay of age)             |
| `importance`   | `importance(candidate, access_weight)` in `[0,1]`            |
| `access_boost` | normalized access-frequency signal (nullable — no signal)     |
| `fused_score`  | the fused rank score the packer ordered by                    |
| `rank`         | 0-based position in the packed set                            |
| `created_at`   | pack time                                                      |

The feature snapshot is captured with the EXACT `now`, `weights`, and
`access_weight` the fused ranker used on that call, so there is no re-derivation
drift between what was ranked and what was recorded.

### The labeled-example join

`talos_memory::fetch_rank_training_examples(pool, actor_id, since, limit)`
returns the training data Phase 2 will consume: each provenance row's feature
snapshot LEFT-JOINed to its execution's OUTCOME label —

- the newest `judge_scores` verdict for that execution (`judge_score`,
  `judge_passed`), via a `LATERAL` "newest verdict" subquery; and
- the `workflow_executions.status` (`execution_status`).

Both outcome sides are `Option` — a provenance row may have no judge verdict
and/or an orphaned execution. This is the (features → label) dataset a learned
per-actor ranker trains on: "which memories, when injected, preceded a good
execution?"

Orphan rows (the execution INSERT after context-pack later failed — the id is
minted before the row is durably created, then admitted under the concurrency
limit which may reject) simply never join in this query and age out via
retention. Harmless.

### The flag

Provenance recording is **default-OFF**, gated by
`ENABLE_MEMORY_RANK_PROVENANCE` (`talos_config::memory_rank_provenance_enabled`).
When OFF, the injection path is byte-identical to today — no provenance rows are
written and the retention sweep loop is not even spawned. Operators can flip it
on to start accruing training data independently of any consumer (Phase 2 does
not exist yet).

Recording is additionally gated on the smart path (`ENABLE_SMART_MEMORY_CONTEXT`)
and on the presence of a real `execution_id` — draft/test previews, the
scheduler, and sub-workflow context resolution pass `None` and record nothing.

### Retention

`MEMORY_RANK_PROVENANCE_RETENTION_DAYS` (default 90, clamped `[1, 3650]`) bounds
how long rows are kept. A background sweep
(`talos_memory::sweep_execution_memory_context`, wired in `main.rs`) deletes
older rows on `MEMORY_RANK_PROVENANCE_SWEEP_INTERVAL_SECS` (default 3600, clamped
`[300, 86400]`). The sweep loop is only spawned when the flag is on.

### Non-blocking

The provenance write is **fire-and-forget** (`tokio::spawn`, best-effort, logged
at debug on error, never propagated) — the exact posture as the Phase-3a
`bump_access` recall-path mutation. It adds ZERO latency to context assembly and
only fires on the flag-ON smart path.

### Privacy posture

- Stores memory **KEYS + numeric feature signals ONLY** — never memory VALUES,
  and no values in logs.
- **Actor-scoped**: every row carries `actor_id`; the training query is
  `WHERE actor_id = $1`.
- **Retention-bounded**: rows age out via the sweep.

## Operating notes / known limitations

- **Provenance depends on `ENABLE_SMART_MEMORY_CONTEXT`.** The per-memory feature
  snapshot (relevance/recency/importance/fused_score) only exists on the
  smart-context path, so `ENABLE_MEMORY_RANK_PROVENANCE=1` records **nothing**
  unless `ENABLE_SMART_MEMORY_CONTEXT=1` is also on. The controller logs a WARN
  at startup if provenance is on while smart-context is off. Coverage is the
  **scheduler** (primary actor-bound path) + the manual trigger path; the
  sub-workflow resolver is a noted follow-up (its `execution_id` isn't in scope
  at that call site yet).
- **Outcome label = newest judge verdict.** `fetch_rank_training_examples` takes
  the most-recent `judge_scores` row per execution (`ORDER BY created_at DESC
  LIMIT 1`). A workflow with more than one judge node collapses to whichever
  judge wrote last — an arbitrary label. Phase 2's learner should treat the
  label as execution-level, not judge-node-scoped, and may want to aggregate
  (e.g. min/mean passed) if multi-judge workflows become common.

## Phase 2 — the learned ranker (future)

Phase 2 will consume `fetch_rank_training_examples` to learn a per-actor
adjustment to the fused score (e.g. a small logistic model over the recorded
features, targeting the judge/outcome label), replacing or reweighting the
global `SMART_MEMORY_CONTEXT_W_*` knobs on a per-actor basis. Phase 1 builds the
substrate only; it does NOT build the model.
