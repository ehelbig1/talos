# RFC 0003 — Durable workflow execution

**Status:** In progress (Phase 1 landed, flag-gated default-off)
**Author:** Platform
**Date:** 2026-05-28

## TL;DR

A workflow that is interrupted mid-run (controller crash, rolling
deploy, OOM-kill) loses its in-memory progress and restarts from
scratch. This RFC makes execution **durable** in stages. Phase 1 —
**per-node checkpointing** — has landed behind
`EXECUTION_CHECKPOINTING_ENABLED` (default off). It is the first step of
a deliberate direction, not a one-off.

The 2026-05-28 architecture review originally recommended "JetStream
ack + redelivery." Investigation showed that is the **wrong fix for the
current model** (details below). The real gap is controller-crash
recovery, and the right tool is checkpointing — which also happens to be
the correct first step toward any future durable-execution architecture.

## The model, precisely

It matters to name what "the engine" is, because "make it durable"
means different things at different layers:

- The **DAG engine runs inside the controller** (`talos-workflow-engine`,
  driven by the scheduler / execution-orchestration). It holds the
  workflow's per-node output map in memory and drives the run to
  completion within one process lifetime. It is **async and parallel**
  (tokio; ~8 concurrent node dispatches) — "synchronous" below refers
  only to the *orchestration/durability* model, not the concurrency
  model.
- Each **node is a signed request/reply RPC to a worker** over core
  NATS (`dispatcher.rs` pre-allocates a reply inbox, signs the
  `JobRequest`, publishes, awaits the reply). Workers are credential-free
  and load-balanced by NATS queue groups.
- The controller has its **own retry loop** (`execute_job_with_retry`):
  worker dies → no reply → timeout → re-dispatch → a surviving
  queue-group worker picks it up.

## Why JetStream-ack is the wrong fix *now*

JetStream pull-consumer + explicit ack provides **at-least-once
delivery to a consumer the producer doesn't wait on** — a decoupled
work queue where the broker owns redelivery via `AckWait`.

That doesn't fit a synchronous request/reply orchestrator:

1. **Redelivery already exists.** Worker-crash is covered by
   `execute_job_with_retry`. JetStream-ack would layer a *second,
   redundant* redelivery onto a model that already has one.
2. **Ack protects the wrong thing.** The state lost in a crash is the
   controller's in-memory DAG progress (the other N−1 completed nodes'
   outputs), not the single in-flight job message. If the controller
   dies, redelivering one node's job produces an orphan result with no
   engine to receive it (the reply inbox is gone) and does nothing for
   the rest of the run.
3. **It collides with two load-bearing invariants.** At-least-once means
   *possible duplicate processing*, so the same `JobResult` nonce can be
   published twice → the `JOB_NONCE_CACHE` "result_nonce already seen"
   failure that CLAUDE.md flags as a **total regression** (every job
   fails). The verify-once / single-publish discipline would need a new
   idempotency scheme that doesn't key on the replay cache.
4. **It's a re-architecture.** Request/reply uses an ephemeral,
   correlated reply inbox per call; JetStream consumers are durable and
   decoupled with no reply correlation. Recovering the engine's
   "await *this* node" semantics on top of JetStream means rebuilding a
   result-routing layer in the dispatcher and worker loop.

Net: large rewrite + invariant collisions + total-regression risk, to
add redundant redelivery that protects the wrong state. **Not now.**

Honest caveat (orthogonal to this choice): neither approach gives
exactly-once. A worker that completes a node's side effects then crashes
before publishing the result is re-run on retry — at-least-once
(JetStream or controller-retry alike) yields a duplicate. The platform
relies on idempotent module design for this.

## The right destination (and the wrong one)

The mature "durable execution" pattern (Temporal) achieves resilience by
**deterministically replaying workflow code** against an event history.
That **requires deterministic workflow logic.** Talos nodes are
**arbitrary user-submitted WASM modules with side effects** — not
deterministically replayable. So an event-sourced replay engine is a
**poor fit for Talos specifically**, and is an explicit non-goal.

Talos's existing approach — **snapshot completed node *outputs*, resume
by re-seeding them** (`CheckpointStore` + `run_with_seed`) — makes no
determinism assumption: it just doesn't re-run nodes whose outputs it
already has. And the engine is **already a hybrid**: `Wait` / approval
nodes suspend → checkpoint → the scheduler resumes them. Per-node
checkpointing simply extends that same mechanism from *planned*
suspensions to *unplanned* interruptions.

In mature systems durability lives in the **state store**, not the task
queue's ack; the queue (which *is* at-least-once with ack, like
JetStream) only dispatches the next task. So the correct ordering is:

> **durable state first (checkpointing) → crash-resumable orchestrator
> → *then*, only if controller-fleet elasticity at scale demands it,
> durable task dispatch (where JetStream-ack finally fits).**

## Phases

| Phase | Shape | Status |
|---|---|---|
| **1** | Per-node checkpointing of completed outputs; resume re-seeds via the existing `run_with_seed` path | **Landed**, flag-gated default-off |
| **2** | Resume on startup: a sweep that finds `running` executions with a checkpoint and re-drives them (today resume is scheduler/`Wait`-triggered only) | Future |
| **3** | Durable task dispatch (JetStream pull-consumer + ack) for controller-fleet elasticity — only if scale demands it; gated on Phase 2 making the orchestrator crash-resumable | Deferred / maybe never |
| — | Event-sourced deterministic replay (Temporal-style) | **Non-goal** — incompatible with arbitrary-WASM-node workflows |

## Phase 1 design (landed)

- **Seam:** `ParallelWorkflowEngine` gains an optional
  `CheckpointConfig { store, every_n, dirty }`. After every `every_n`-th
  node completion (in `engine_completion.rs::handle_node_success`, which
  also handles pipeline-chain tails), a snapshot of all completed-node
  outputs is **spawned** to `store.save()` — non-blocking, best-effort
  (failure logs, never propagates).
- **Top-level only, by construction:** the store is wired only by the
  canonical builder (`talos-engine/src/builder.rs::build_controller_engine`).
  Sub-workflow engines hydrate via `adapter_set().into_engine()`, which
  deliberately does **not** carry the field — so a child can never
  checkpoint under the parent's `execution_id`. (No fragile depth check.)
- **Reuses existing crypto:** `ControllerCheckpointStore` (AES-256-GCM,
  HKDF subkey from `WORKER_SHARED_KEY`, `workflow_executions.checkpoint_*`
  columns) — identical to the scheduler's completion-time checkpoint,
  plus `SecretsManager` for the DEK-column load fallback.
- **Default off:** with no store wired the engine is byte-identical to
  pre-RFC behaviour. Blast radius while off is zero.
- **Knobs:** `EXECUTION_CHECKPOINTING_ENABLED` (default `false`),
  `CHECKPOINT_EVERY_N_NODES` (default `1`).

### Known trade-offs

- **Cadence vs. cost.** `every_n = 1` re-encrypts the growing snapshot
  on every node — fine for typical graphs (< ~50 nodes), O(n²) bytes on
  pathological ones. Raise `CHECKPOINT_EVERY_N_NODES` there; resume then
  re-runs up to N trailing nodes.
- **Last-writer-wins.** Saves are spawned and may complete out of order
  under contention; a stale snapshot only costs re-running a few nodes
  on resume (best-effort by design).
- **Granularity.** Pipeline-batched linear chains are atomic dispatch
  units — they checkpoint at the chain boundary, not mid-chain (you
  can't resume into the middle of one job anyway).

### Tests

`talos-workflow-engine/tests/checkpointing.rs`: (1) persists all
completed-node outputs at `every_n=1`; (2) `every_n=0` / unwired writes
nothing; (3) the snapshot is a valid resume seed — re-feeding it makes
`run_with_seed` skip re-dispatching seeded nodes.

## Staging validation runbook (before enabling in prod)

End-to-end crash recovery cannot be unit-tested; validate on a staging
cluster:

1. `WORKER_SHARED_KEY` set (controller + worker, same value);
   `EXECUTION_CHECKPOINTING_ENABLED=true`; pick a `CHECKPOINT_EVERY_N_NODES`.
2. Trigger a multi-node workflow with an artificial delay (a `wait`-free
   graph of ≥5 module nodes, each sleeping a few seconds).
3. Mid-run, `kubectl delete pod` the controller (or `kubectl rollout
   restart deploy/talos-controller`).
4. Confirm the execution row carries `checkpoint_encrypted` +
   `checkpoint_nonce`.
5. Re-drive the execution (Phase 1: via the scheduler/resume path or a
   manual `replay`/resume) and assert from `node_executions` /
   dispatch counts that **already-completed nodes are not re-run** and
   the workflow completes.
6. Compare final output against a clean (un-interrupted) run.
7. Load-test with `every_n=1` on a representative large graph; watch the
   `talos_db_pool_*` gauges and checkpoint-save WARN rate. Tune
   `CHECKPOINT_EVERY_N_NODES` up if pool pressure or save latency climbs.
8. Only then flip `EXECUTION_CHECKPOINTING_ENABLED=true` in production.

## See also

- `docs/deployment.md` → High Availability & SPOF, Optional Configuration
- `talos-engine/src/checkpoint_store.rs`, `talos-workflow-engine/src/engine_completion.rs`
- CLAUDE.md → "Verify-once rule for signed NATS messages" (the invariant
  the JetStream-ack path would have collided with)
