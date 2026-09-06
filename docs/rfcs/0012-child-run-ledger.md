# RFC 0012 — A ledger for sub-workflow runs

**Status:** P1 implemented (2026-09-06)
**Author:** Platform
**Date:** 2026-09-06

## Motivation

`execute_subworkflow_graph` runs a child workflow IN-PROCESS and records no
`workflow_executions` row. Measured on the reference fleet 2026-09-05: zero rows
carrying `parent_execution_id`, live table and archive, platform-wide, against an
estimated ~225 child runs per day (98.6% of them one workflow). Every reader that
answers "did this workflow run, how often, how reliably, how recently?" reads
`workflow_executions` — 163 occurrences across 28 non-test files — so a child is
structurally invisible to all of them. #758/#760/#762/#763 taught the DESTRUCTIVE and
SCORING readers to say "no evidence" instead of "never ran" (dormant delete advice,
stale-draft archive/delete, readiness scored on a 30-point scale, reuse stats,
schedule suggestion, risk assessment). What none of them can do is ANSWER the
question. `last_child_activity_at` on the hygiene report is a proxy from
`execution_cost_rollup` with measured ~5% coverage; on the flagship's daily child it
reads six weeks stale while the parent ran 463 times in 48 h.

Two shapes were considered for the answer.

**A. Record children in `workflow_executions`.** Rejected. 161 of the 163 reads carry
no `parent_execution_id` filter, so every fleet total, error rate and cost aggregate
would double-count from the first child run; `budget_precheck` counts execution rows
against `max_executions_per_hour`, so a parent with a `team_gather` child would be
charged twice for one run; the retention sweep archives by row, so a tree would be
split across tiers at day 30; and the row shape (32 columns, ciphertext output,
approval tokens, checkpoints) is far more than a child run needs.

**B. A separate, narrow table written at the dispatcher chokepoint.** Chosen. This RFC.

## Design

### Table `sub_workflow_runs`

| column | type | notes |
|---|---|---|
| `id` | uuid PK | |
| `parent_execution_id` | uuid NOT NULL | **no FK** — see retention |
| `parent_workflow_id` | uuid NOT NULL | denormalised so a purged parent still answers "who ran me" |
| `parent_node_id` | text NOT NULL | the graph node id, control-char-scrubbed, ≤120 bytes |
| `dispatch_kind` | text NOT NULL CHECK IN (`sub_workflow`,`judge`,`ensemble`,`reflective_retry`,`llm_dispatch`) | DERIVED FROM THE CODE (see "What the chokepoint cannot see"): exactly the kinds whose dispatcher routes through the chokepoint. `agent_loop` was in this list when the RFC was drafted and is NOT admitted by the CHECK — it has no writer, and a value nothing writes is the same defect as a seeded metric label nothing increments |
| `child_workflow_id` | uuid NOT NULL | |
| `user_id` | uuid NOT NULL | tenancy |
| `actor_id` | uuid NULL | the EFFECTIVE actor the child ran as (after `bind_subengine_actor_and_ceilings`) |
| `depth` | smallint NOT NULL | nesting depth, 1 = direct child |
| `started_at` / `completed_at` | timestamptz | |
| `status` | text NOT NULL CHECK IN (`completed`,`failed`) | |
| `error_class` | text NULL | ≤512 chars, DLP-redacted via the same path as `workflow_executions.error_message`; NEVER the payload |
| `duration_ms` | bigint | |

**Amended during implementation, from code facts measured before anything was
written.** Three of this section's first draft did not survive contact:

* **`org_id` is DROPPED.** `ParallelWorkflowEngine` has no org handle at the
  write site — it carries `user_id`, `actor_id` and `workflow_id` and nothing
  else tenant-shaped — so the column could only be filled by an extra query per
  child run. It would also be the same unreliable tenant key `20260904210000`
  documents on the archive: that policy joins `workflows` for the org rather
  than trusting the row's own column, and this table's policy does exactly the
  same, joining on `parent_workflow_id`. The column would have been decorative
  and wrong.
* **`agent_loop` is NOT in the CHECK.** See "What the chokepoint cannot see".
* **`started_at` / `completed_at` reach the repository as UNIX milliseconds.**
  `talos-workflow-engine-core` is the portable engine core and carries no
  date-time dependency; adding one to it for a timestamp the repository can
  reconstruct exactly would be the wrong direction.

**No output payload, no input payload.** The ledger answers "ran / when / how / for
whom"; the child's output already lives in the parent's node result. No new
ciphertext table, nothing new to re-encrypt per org, nothing for DLP to miss.

Indexes: `(child_workflow_id, started_at DESC)`, `(parent_execution_id)`,
`(user_id, started_at DESC)`. Nothing else until a reader measures a need.

### What the chokepoint cannot see

**The RFC's premise that `execute_subworkflow_graph` is the ONE path every child
takes is REFUTED, and the correction is load-bearing.** Every
`AdapterSet::into_engine_with_graph` site in the workspace was enumerated
2026-09-06 — that call is the only way a child graph becomes a running engine —
and there are THREE:

| site | reaches the chokepoint? |
|---|---|
| `engine_dispatch_subflow.rs` `execute_subworkflow_graph` | IS the chokepoint |
| `scheduler_handlers.rs` `run_dispatched_subworkflow` (`dispatch`, `capability_dispatch`) | **no** |
| `scheduler_handlers.rs` agent-loop / ReAct-loop body, per iteration | **no** |

So P1 records five node kinds and is structurally blind to four
(`agent_loop`, `react_loop`, `dispatch`, `capability_dispatch`). On the
reference fleet those are LATENT — of 36 workflows the only child-dispatching
node kinds present are `sub_workflow` (3) and `judge` (3), both recorded — and
"latent is not live" cuts both ways, so the gap is NAMED
(`talos_child_run_ledger::UNRECORDED_DISPATCH_KINDS`) and DISCLOSED by every
consumer rather than left to read as "this child never ran". Covering them is
P2; the agent-loop body runs inside an `async move` that captures the adapter
set rather than `self`, so it needs a different shape.

### Writer — ONE chokepoint

Inside `execute_subworkflow_graph` (eight call sites reach it; the call sites are
NOT the chokepoint).

**The parent's identity is threaded in, because it is not readable there.**
`ParallelWorkflowEngine` has NO `execution_id` field — it is a parameter of
`run_inner`, and nodes dispatch concurrently, so ambient interior-mutable state
would be both a race and a lie. `parent_node_id` and `dispatch_kind` are
likewise unknown at the chokepoint. A `Copy` `ChildRunSite { execution_id,
node_id }` is therefore threaded from the reactor loop through the five
`try_dispatch_*` / five `dispatch_*` handlers, and each dispatcher names its own
`ChildDispatchKind` at the call. It is an ENUM with an explicit `Untracked`
variant, not an `Option`, so a sixth handler cannot be added without the
compiler asking where it came from — and the WRITE still happens in exactly one
place. The existing precedent is `record_judge_score(node_id, execution_id, …)`,
which takes both as arguments for the same reason.

**Pre-run failures are NOT child runs.** The clock starts where the child engine
starts. A missing graph or a build failure gets no row — it surfaces in the
parent's node output as an error envelope, and recording it would put a "failed
run" in the ledger for a child that never started.

**`status` is CLASSIFIED, not shape-assumed.** A child whose engine returned
`Ok` can still have failed: its collapsed output may carry an error envelope.
The ledger uses `reserved_keys::output_reports_error` — check 77's shared
classifier, the same one the reactor uses to decide the parent node's fate — so
the ledger and the run cannot disagree about whether a child failed.

A `ChildRunRecorder` trait in `talos-workflow-engine-core`,
modelled on `JudgeScoreRecorder`: impls must not return errors to the engine. The
controller-side impl lives in a leaf repository crate (`talos-child-run-ledger`)
with a thin adapter in `talos-engine`, and writes one INSERT after the child
settles. A record failure is logged with `event_kind = "child_run_record_failed"`
and counted on a PRE-SEEDED counter (`talos_child_run_record_failures_total`, absent ≠
zero) and NEVER changes the child's or the parent's outcome — a ledger must not
become a routing dependency.

**Explicitly NOT counted against the actor's hourly execution budget.** A child is
part of the parent's run, which was budgeted when it was created; fuel and cost are
already rolled up per node. Recorded here so nobody "fixes" it.

### Retention

No FK to `workflow_executions`: archival is a DELETE from the live table plus an
INSERT into the archive, so `ON DELETE CASCADE` would erase the ledger at day 30 while
the parent survives to day 60. The ledger keeps its own retention in the existing
retention pass: delete rows older than the TOTAL lifetime
(`archive_after_days + purge_after_days`), batch-limited with `SKIP LOCKED`, exempting
rows whose parent is pinned in either tier. Positive-days guard as `purge_archived_executions`.

### `ledger_since` — UNKNOWN is not zero

The table has a first row. Every reader MUST be able to say "the ledger started on
D"; a query returning 0 rows for a period before D is UNKNOWN, not "0 runs" — the
same rule #758 applies to `child_workflow_ids_checked`. P1 exposes
`ChildRunLedger::since()` (min `started_at`, cached per process for 60 s) and every
consumer renders it beside its count.

`since()` is deliberately NOT user-scoped, and it is the one read that crosses a
tenant boundary. The question is *"from when was anything being recorded"*,
which is a deployment fact; a per-user `MIN` answers a different question and
would render UNKNOWN forever for a user who has legitimately never dispatched a
child — turning a real zero into a permanent "we cannot tell". What crosses is
ONE timestamp with no tenant attached. Note also what it cannot say: retention
raises the floor, so it is *"the earliest run the ledger still holds"*, which is
the conservative direction — it can only widen the UNKNOWN region.

### Security & tenancy

RLS from the first migration (the archive table shipped without it and held tenant
ciphertext — #748). Every read is `WHERE user_id = $N` on the app layer AND under RLS.
`error_class` passes through the same redaction as execution error messages and is
capped before the bind. `parent_node_id` is scrubbed the way the hygiene report scrubs
node ids. Nothing in the row is a secret and nothing is encrypted, because nothing in
the row is content.

### Performance

One INSERT per child run (~225/day today; 10× that is still nothing), three
indexes, a batch-limited retention delete. The write is awaited after the child
settles, on the parent's task, so it adds one round trip (~0.5 ms) to a run that
took seconds; it is not spawned, because a spawned write is the orphaning shape
`docs/platform-primitive-checklist.md` warns about.

## Phasing

- **P1 (this RFC's PR, IMPLEMENTED):** migration + RLS, `ChildRunRecorder` trait + repo impl, the
  chokepoint write, retention, `since()`, and the two SMALLEST honest consumers:
  `get_execution_lineage` lists child runs under their parent (kind, child, status,
  duration), and `get_workflow_reuse_stats.parent_dispatched` gains
  `child_runs_since_ledger` with `ledger_since` beside it. Both are additive keys.
- **P2:** the four uncovered dispatch kinds above; readiness — `ReadinessBasis::ParentDispatched` gains measurable reliability and
  freshness from the ledger once it holds ≥ N rows for that child, restoring the
  100-point scale with the basis named; hygiene `last_child_activity_at` from the ledger
  instead of the 5%-coverage rollup proxy; the dormant/stale-draft lists gain
  `last_child_run_at`.
- **P3:** SLA monitor and `get_workflow_risk_assessment`'s cascading check read the ledger.

## Alternatives considered

Recording into `workflow_executions` (above). A `parent_execution_id`-filtered VIEW over
`workflow_executions` (requires A first). Reading `execution_cost_rollup` (measured 5%
coverage, and it lands under a synthetic workflow id). Making `judge_scores` the
ledger (judge-only; four other dispatch kinds).
