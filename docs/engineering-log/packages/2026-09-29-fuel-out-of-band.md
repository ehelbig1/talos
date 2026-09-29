# 2026-09-29 — the hourly fuel budget counted only completed object outputs

**Found live** while proving modules run after the Wasmtime 49 deploy: a JSON
Transform run that returned an array had no `module_executions.fuel_consumed`.
2 of 36 153 completed module rows in 30 days, both JSON Transform. The row
was the visible symptom; the budget was the defect.

**Cause.** The worker stamps `__fuel_consumed__` / `__fuel_limit__` into the
module's OUTPUT, and only when that output is a JSON object
(`talos-worker-runtime/src/runtime.rs`, three sites). Both fuel ledgers read
the figure back out of the output:

- `execution_cost_rollup`, from `ControllerNodeHook::on_node_completed`;
- `module_executions.fuel_consumed`, from the engine store's `record_completed`.

The actor's hourly fuel budget (`max_fuel_per_hour`) sums the first. So fuel
the budget never saw:

| Spend | Why it was invisible |
|---|---|
| a non-object output (array, string, number) | nowhere to stamp it |
| a failed, timed-out or fuel-exhausted attempt | no output; the hook fires on completion only |
| a retried attempt | only the final attempt's output reaches the engine |
| a loop-body iteration | no lifecycle hook runs per iteration |
| a module-bound dispatch (webhook, push, DLQ replay) | not an engine node at all |

The per-run fuel cap still held. The hourly aggregate was blind, and a
module could choose its own output shape.

**Operator decision 2026-09-29: budget-complete scope.** Every way to spend
fuel the budget cannot see is closed, not only the reported shape.

**Decided.**
- **One resolution rule**, `talos_workflow_job_protocol::spent_fuel`: the
  signed out-of-band figure wins whenever present; otherwise the in-band key
  is read, so a worker that predates the field is counted exactly as before;
  never both; zero is not a measurement.
- **A signed carrier.** `JobResult::fuel` and `PipelineStepResult::fuel`
  (`FuelMeasure { consumed, limit }`), conditional-append at the END of each
  signing payload (`:fuel=<c>/<l>`, `:step_fuel:<hash>`). Absent is
  byte-identical to the pre-field format. Present is bound, so an on-wire
  tamperer cannot deflate an actor's budget figure. `worker_id` cannot hold
  `:`, so the segment cannot be forged from it.
- **Recorded per verified attempt at the dispatcher**, the precedent the LLM
  token ledger already set: a `FuelSink` on `NatsNodeDispatcher`, fired for
  every verified `JobResult` (success or failure, first attempt or retry,
  loop bodies included since they share the dispatcher) and per pipeline
  step. Identity comes from the CONTROLLER's `DispatchJob`, never the worker.
  `execute_job_with_retry`'s LLM hook became one per-verified-result hook
  that feeds both sinks.
- **One writer of both ledgers**, `talos_cost_attribution`
  (`record_dispatch_fuel`, `record_module_bound_fuel`). A retried attempt of
  one row ADDS to its `fuel_consumed`. The in-band reads in the node hook and
  `record_completed` are removed, so nothing is counted twice. `record_fuel`
  is deleted.
- **`DispatchJob` gained `workflow_id` and `node_label`**, controller-side
  attribution only, never on the wire. Both come from the one engine method
  `cost_attribution_workflow_id`, the same value the completion context
  carries, so a sub-workflow node stays attributed to the sub-workflow (the
  `JOIN workflows` in every fuel report is the tenancy predicate).
- **Module-bound paths** (webhook router, result observer) record through the
  same crate, with identity read from the attempt's own `module_executions`
  row inside the recording statement.
- **Migration `20260929120000`**: `execution_cost_rollup.outcome`
  (`completed | failed`, CHECK, default `completed`, which describes every
  existing row), and `workflow_id` / `node_id` nullable for module-bound
  rows. The budget sums every row. The five LEARNERS read `completed` only:
  adaptive fuel ceilings, the fuel usage report, the high-utilisation
  detector, the timing fallback and the fuel-exhaustion advisor. A
  fuel-exhausted attempt sits at its limit, so feeding it to a learner would
  raise the learned ceiling after every exhaustion.
- **Two PRs, no lockstep deploy.** PR A (this one) carries the protocol, the
  controller and the migration; with no worker change it falls back to the
  in-band figure and already counts loop bodies and retried attempts that
  stamp one. PR B makes the worker emit the field, including on failure. A
  controller that knows the field verifies results with or without it.

**Stated changes in meaning.**
- `execution_cost_rollup.wall_time_ms` is now the WORKER's per-attempt
  execution time (`JobResult.execution_time_ms`, `Instant`-based) instead of
  the engine's node dispatch time. The column comment says so.
- Retried attempts now each have a rollup row, so per-execution cost totals
  include the fuel retries spent. That is the intended accounting.

**Stated limits.**
- **Until PR B deploys**, a failed attempt and a non-object output still
  carry no fuel.
- **Pipeline steps** carry no `module_executions` row id in `DispatchJob`, so
  a step's fuel reaches the rollup and the budget but not its row's
  `fuel_consumed`. The chain path is dormant by config.
- **The result observer** verifies with `verify_no_replay` (its role), so a
  replayed result from a holder of the fleet key would be recorded twice.
- **No test drives a real worker over real NATS.** The dispatcher tests drive
  the production `dispatch()` against a signing transport.

**Proof.**
- Protocol: absent fuel signs byte-identically and is omitted from the wire;
  present fuel is appended verbatim at the end (`:fuel=1234567/5000000`); a
  lowered, raised, re-limited or stripped figure fails verification; the
  pipeline twin binds each step's figure to its position; the resolver's
  precedence, fallback and zero rules; a non-default wire JSON snapshot.
- Dispatcher, driven through the production `dispatch()` against a signing
  transport: a failed, a fuel-exhausted and an array-output success attempt
  each reach the sink, in order, with the controller's identity; a pre-field
  result is counted once from its in-band figure; a result without fuel
  records nothing (negative control).
- Database, on a disposable migrated Postgres: a failed attempt's fuel makes
  the real admission refuse at `max_fuel_per_hour` (control admitted before
  it); both ledgers record each attempt and a row sums its retries; a
  module-bound record takes its identity from the row and an unknown row
  writes nothing; adaptive stats ignore failed attempts; a failed result
  driven through the production result observer reaches both ledgers.
- Check 88 PREPAREs all 1 239 static statements against the migrated schema,
  including the new ones. `nextest` over the 14 touched crates: 2 338 passed.
  The controller DB tests that touch either ledger pass.
- **Mutations: 9 applied, 9 caught**: the sink firing on success only; the
  budget counting completed rows only; the resolver preferring in-band; a
  failed attempt mapped to completed; the adaptive learner reading failed
  rows; fuel dropped from the signature; the observer recording nothing; the
  recorder skipping the row; the production dispatcher built without the
  sink.

**Not covered by a behavioural test, stated.** The webhook router's call is
not driven (the router needs a broker and a verified reply); the observer
test drives the same recorder through the other module-bound site. The
controller's install call is a TEXTUAL pin, because `main.rs` is not reachable
from a test.
