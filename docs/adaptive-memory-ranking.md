# Adaptive per-actor memory ranking

The smart-context retriever (`get_relevant_actor_context_smart`) ranks an
actor's memories by a fixed, hand-tuned fused score (relevance + recency-decay +
importance, weighted by `SMART_MEMORY_CONTEXT_W_*`). The weights are global —
they don't adapt to whether a given actor's memories actually led to good
execution outcomes.

**Adaptive memory ranking** is the multi-phase effort to LEARN a per-actor
ranking from outcome signals. This document describes **Phase 1: the provenance
foundation** — the observe-only substrate that records what was ranked (Phase 1
changes NO ranking behaviour) — and **Phase 2: the learned ranker** — the
per-actor logistic model that consumes that substrate to adapt the fused-ranking
weights (default-OFF; flag-off ⇒ byte-identical ranking).

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

## Phase 2 — the learned ranker

Phase 2 LEARNS per-actor fused-ranking weights from the Phase-1 provenance
corpus, replacing the global `SMART_MEMORY_CONTEXT_W_*` constants — on a
per-actor basis — with weights adapted to which memories actually preceded good
outcomes for THAT actor. It lives in the `talos-memory-ranking` crate.

### The one-model insight

The ranker's fused score is
`w_rel·relevance + w_rec·recency + w_imp·importance` (with `access_weight`
folded into the importance term). A per-actor **logistic regression over the
SAME features** `[relevance, recency, importance, access_boost]`, fit to predict
the outcome label, yields coefficients that ARE the adaptive per-actor weights —
so "learned importance" and "adaptive weights" are ONE model.

### The model

- **Feature vector** (per Phase-1 example): `[relevance, recency, importance,
  access_boost.unwrap_or(0.0)]` — the exact recorded signals. `rank` and
  `fused_score` are deliberately EXCLUDED (they are OUTPUTS of ranking, so
  including them would be circular).
- **Label**: outcome-linked. A judge verdict wins (`judge_passed` → 1.0/0.0);
  otherwise `execution_status` maps `completed → 1.0`, `failed`/`cancelled →
  0.0`; any other status (`running`/`pending`/`resuming`/none) is unlabeled and
  the example is skipped.
- **Sample weight**: judge-labeled examples weight `1.0`; status-only examples
  weight `0.3` (the weaker signal).
- **Fit**: a compact L2-regularized, sample-weighted binary logistic regression
  via full-batch gradient descent (500 epochs, lr 0.1, L2 1e-3), mirroring
  `talos-ml`'s `linear.rs` gradient shape (mean gradient + weight decay, bias
  unregularized). Fit on **RAW** features — all four already live in `[0,1]`, so
  they need no standardization, and the ranker multiplies the coefficients by
  those same raw features, keeping the coefficient→weight mapping a clean
  identity. `feature_mean`/`feature_std` are recorded on the artifact for
  observability but are NOT applied at serve time.
- Returns **`None`** (→ keep global defaults, write NO model) when there is no
  learnable signal: fewer than `ADAPTIVE_RANK_MIN_EXAMPLES` (default 50) usable
  examples (cold-start), a single-class label set (no contrast), or a
  non-finite fit (degenerate).

### The coefficient → fused-weight mapping

The logistic coefficients are on the logit scale and CAN be negative; the fused
ranker needs NON-NEGATIVE weights. Per base signal
(relevance/recency/importance): `fused_weight = coefficient.max(0.0)`, then
clamp to `[0, FUSED_WEIGHT_MAX]` (1e6, mirroring the config weight cap).
Rationale: all three base signals SHOULD be positively predictive; a negative
coefficient is overfit noise, so it gets weight 0 (drop the signal) — never a
negative weight that would INVERT the ranking. `w_access` maps to the
`access_weight` arg, clamped `[0,1]`. Non-finite inputs degrade to 0
(NaN/Inf-safe). The recency **half-life is NOT learned** — it is kept from the
global config; the model learns only the 3 blend weights + the access weight.
`rank_weights_to_fused` produces the `(Weights, access_weight)` serving pair.

### Storage (`actors.metadata.rank_weights`)

The learned model is stored as a JSON blob under the RLS-isolated
`actors.metadata` JSONB column:

```json
{ "w_relevance": 1.2, "w_recency": 0.4, "w_importance": 0.9, "w_access": 0.2,
  "bias": -0.1, "feature_mean": [..4..], "feature_std": [..4..],
  "n_examples": 73, "fitted_at": "<rfc3339>" }
```

`ActorRepository::set_actor_rank_weights` writes it via
`jsonb_set(COALESCE(metadata,'{}'), '{rank_weights}', $2)` (preserving every
other metadata key); `get_actor_rank_weights` reads
`metadata->'rank_weights'`. Both key STRICTLY on `actor_id`.

### The training job (why no tier gate)

`spawn_rank_training_scheduler` (wired in `main.rs` next to the consolidation
scheduler) is **default-OFF** — it returns without spawning when
`ENABLE_ADAPTIVE_RANK_TRAINING` is unset. When on, a teacher-audit-shaped loop
(interval + `MissedTickBehavior::Delay` + biased-shutdown `select!`) runs every
`ADAPTIVE_RANK_TRAINING_INTERVAL_SECS` (default 6h). Per tick it scans up to
`ADAPTIVE_RANK_MAX_ACTORS_PER_TICK` (default 50) active actors; for each it
fetches that actor's Phase-1 examples within `ADAPTIVE_RANK_LOOKBACK_DAYS`
(default 30), builds the labeled set, fits, and — only on `Some(model)` —
persists it. `None` fits skip the actor at debug (it stays on global defaults).

Unlike consolidation and reflection, the training fit is a **pure numeric
computation over the Phase-1 numeric signals only** — memory KEYS and feature
scalars, never memory VALUES — and makes NO external call. There is therefore
zero data egress, so **no `max_llm_tier` gate applies** (a tier-1 actor's
private memory content never enters the fit).

### Serving injection + cold-start fallback

At the ranker seam (`WorkflowRepository::get_relevant_actor_context_smart`),
BEFORE building the fused `Weights`: when `ENABLE_ADAPTIVE_RANK` is on, the
smart path calls `talos_memory_ranking::load_serving_weights(pool, actor_id)`.
That returns the learned `(Weights, access_weight)` ONLY when a model exists,
parses, is backed by ≥ `ADAPTIVE_RANK_MIN_EXAMPLES` examples, and maps to at
least one non-zero base weight. **Every other case** — flag-off, no model,
parse-fail, too-few-examples, an all-zero (fully-degenerate) mapping, or any DB
error — falls back to the EXACT global-config weights. So **flag-off (and
cold-start) ranking is byte-identical to today**; the learned weights change
only the fused SCORE ORDER, and `pack_within_budget` + everything downstream is
unchanged.

### Safety bounds

- **Per-actor isolation** — training reads only `WHERE actor_id = $1` examples
  (Phase-1 query) and writes only that actor's `metadata` (`set_actor_rank_weights`
  keys on `actor_id`). One actor's outcomes can NEVER move another's weights.
  RLS on `actors` is a defence-in-depth backstop.
- **Bounded weights** — mapped fused weights are non-negative and capped at
  `FUSED_WEIGHT_MAX`; access weight is `[0,1]`; a degenerate fit can't produce
  Inf/NaN/negative weights (clamped at the mapping; the ranker's own NaN guards
  are a further backstop).
- **Cold-start** — below the min-examples gate or single-class ⇒ global
  defaults (never a half-trained model).
- **No poisoning by one execution** — batch re-fit over a lookback window (not
  online per-execution), L2 regularization, and the min-examples gate together
  bound any single outcome's influence.
- **Default-OFF** both flags; flag-off ⇒ identical behaviour + no training task.

### Config knobs

| env var | default | meaning |
| ------- | ------- | ------- |
| `ENABLE_ADAPTIVE_RANK` | off | SERVING switch — use learned weights when present |
| `ENABLE_ADAPTIVE_RANK_TRAINING` | off | spawn the scheduled fit job |
| `ADAPTIVE_RANK_MIN_EXAMPLES` | 50 (`[10, 100000]`) | min usable examples to fit / trust |
| `ADAPTIVE_RANK_TRAINING_INTERVAL_SECS` | 21600 (`[300, 604800]`) | fit-job wake interval |
| `ADAPTIVE_RANK_LOOKBACK_DAYS` | 30 (`[1, 3650]`) | training window |
| `ADAPTIVE_RANK_MAX_ACTORS_PER_TICK` | 50 (`[1, 500]`) | actors fit per tick |
