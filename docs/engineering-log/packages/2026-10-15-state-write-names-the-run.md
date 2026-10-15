# A durable state write names the run, and the gates' tests run in CI (2026-10-15)

Security review 2026-10-15 (round 2), findings **B2-1**, **D2-2** (Medium),
**B2-5 / D2-3**, **D2-4** (Low) and **B2-7** (Info). Package R1 of the
round-2 remediation.

## The defects, as verified

- **B2-1.** `worker/src/main.rs` builds the execution context as
  `(workflow_execution_id, job_id, module_uri)`; `TalosContext::execution_id`
  is the second, the job's own `module_executions` row. The state host passed
  that id to `spawn_state_write_through`, and the controller's one write
  statement (`execution_state_write`) asks `workflow_executions WHERE id = $1`.
  A node's job id is never a run id, so every honest `state::set` /
  `state::delete` was answered `NotLive`, WARNed, and counted
  `talos_rpc_calls_total{subject="talos.state.write",outcome="not_found"}`.
  The B-3 refusal counter could not tell an attack from the fleet.
- **D2-2.** `talos-rpc-subscribers/src/data_plane_tenancy_db_tests.rs`
  returns early without `TALOS_TEST_DATABASE_URL`; no `lib-migrated` item in
  `scripts/test-integration.sh` named it, and `scripts/ci_test_targets.py`
  classified only `tests/` binaries. The mutation-proved B-3 and B-4/D-2
  gates ran green over zero assertions in CI.
- **B2-5 / D2-3.** `guest_reply` mapped `QueryError` to one sentence and
  passed `ConnectionFailed` through: the guest saw the guest role's name,
  "SET LOCAL ROLE failed: …" with Postgres' text, and the fence refusals.
- **D2-4.** `handle_query_paginated` recorded its `admin_event_log` row only
  after a successful read; a refused or failing statement left nothing.
- **B2-7.** The admission record names
  `intake_tests::a_message_is_not_parsed_without_an_admission_slot`, which the
  same-day follow-up had replaced.

## Decided

- **`execution_state.execution_id` IS the run** (`workflow_executions.id`),
  as the liveness check, the archival move and the orphan sweep already said.
  The state host passes both ids its context holds, and
  `talos_memory::state_rpc::StateWriteRequest::for_dispatch` names the run
  through `durable_state_run`. Keys were already scoped by module
  (`scoped_state_key`), so nodes of one run do not collide; the per-execution
  quota (1 000 keys, 16 MiB) is now per run, which is what "the run's quota"
  means.
- **A module-bound dispatch keeps no durable state.** Every module-bound
  `JobRequest` (webhook router ×2, Google Cloud push) sends its own id as
  `workflow_execution_id`; there is no run to be live, and nothing reads
  `execution_state` back. `durable_state_run` answers `None` when the two ids
  are equal, and the worker sends nothing — so a `NotLive` on the counter is
  now only a write for a run that ended, or a forged one. Chosen over the
  review's alternative (resolve liveness through `module_executions me JOIN
  workflow_executions e ON e.id = COALESCE(me.workflow_execution_id, me.id)`),
  which still finds no run for a module-bound row and would add a join to a
  hot write.
- **A connection or fence failure reaches the guest as one sentence**,
  `GUEST_CONNECTION_FAILED` ("database unavailable"); the detail is logged at
  the subscriber (`event_kind = "database_rpc_guest_connection_failed"`). It
  carries no guest literal, unlike a query error's text, so it is logged.
- **Every `query_paginated` statement that reaches the gate is recorded**,
  with an outcome: `refused` (the gate, or an argument travelling with it),
  `failed` (it ran and failed, or its rows could not be encoded), `returned`
  (`row_count`). `admin_event_log` is append-only (trigger
  `trg_admin_event_log_immutable`), so "record before, update after" is not
  possible; the row is written once the outcome is known, and a statement that
  returns rows is still recorded BEFORE they are handed out. All three hash
  the statement as the caller sent it (the gate trims it), so one statement
  has one hash whatever came of it. A caller who is not a platform admin is
  refused before the gate and records nothing.
- **The admission step is one function**, `kernel::intake`; the loop calls it
  and the restored test drives it. `spawn_rpc_subscriber`'s handler bound
  gains `Sync` (the step holds the handler across the admission wait); every
  handler is a closure over pools and `Arc`s.

## One home

- The run a dispatch's durable state belongs to:
  `talos_memory::state_rpc::durable_state_run`, reached only through
  `StateWriteRequest::for_dispatch` (the worker) — the DB test builds its
  request through the same function.
- What a verified state write does: `talos_rpc_subscribers::apply_state_write`.
- What a guest is told: `guest_reply` (`GUEST_QUERY_FAILED`,
  `GUEST_CONNECTION_FAILED`).
- A library test that needs a service and the runner that provides it:
  `scripts/ci_test_targets.py check` (now also over `src/`), read by check 64.

## The new lint leg

`ci_test_targets.py check` refuses a file under a crate's `src/` that reads a
`TALOS_TEST_{DATABASE,REDIS,NATS}…` variable as a string literal and that no
`lib` / `lib-migrated` filter in `scripts/test-integration.sh` names (cargo's
substring rule over the file's module path, its inline `mod`s and its `fn`s),
unless it carries `// ci-ungated: <reason>`. A doc-comment mention is not a
read. Covered by `ci_test_targets.py --self-test` (in `make test-scripts`).

Measured on the pristine tree (96d86205): 12 `src/` files mention such a
variable; 10 read one; 3 were named by no filter — all three true positives,
0 false positives:

| File | What it is | Now |
|---|---|---|
| `talos-rpc-subscribers/src/data_plane_tenancy_db_tests.rs` | D2-2 | `lib-migrated … --lib data_plane_tenancy_db_tests` |
| `talos-replay-guard/src/lib.rs` | the two live-Redis cross-replica single-use tests | `lib … --lib` [redis] |
| `talos-workflow-engine-nats/src/transport.rs` | `call_site_converts_a_real_503_into_an_error` | `lib … --lib call_site_converts_a_real_503_into_an_error` [nats] |

## Tests

- `data_plane_tenancy_db_tests::a_state_write_built_as_the_worker_builds_it_lands_for_a_live_run`
  — a `module_executions` row under a `running` run; the request built by
  `StateWriteRequest::for_dispatch` from the two ids the worker's context
  holds, verified, applied by `apply_state_write`: one row keyed on the run,
  none on the job; the same request from a node of a `completed` run is
  `NotLive` for set and delete and writes nothing; a module-bound dispatch
  is `NoRun` and sends nothing.
- `state_rpc::durable_state_run_tests` (unit).
- `data_plane_tenancy_db_tests::a_guest_query_error_reaches_the_guest_as_one_sentence`
  extended with a guest role that does not exist (the raw error names it; the
  guest is told `GUEST_CONNECTION_FAILED`).
- `guest_fence_tests::a_fence_failure_reaches_the_guest_as_one_sentence`
  (unit, so the unit job holds it too).
- `controller/tests/admin_query_record_tests.rs::a_refused_or_failed_statement_is_recorded_too`
  — through `advanced::dispatch` as a platform admin: a `DELETE` the gate
  refuses and a `SELECT` of a missing column each leave one row, by hash, with
  the page and no text; a non-admin leaves none.
- `kernel::intake_tests::a_message_is_not_parsed_without_an_admission_slot`.
- All the `lib-migrated` DB tests ran against a migrated clone
  (`scripts/dev-test-db.sh up`, a database created from the `talos_ctl`
  template) and appear in `TALOS_IT_LIST_ONLY=1 bash scripts/test-integration.sh`.

## Mutation proof

| Gate | Mutation | Test | Verdict |
|---|---|---|---|
| state write names the run | `durable_state_run` returns the job id | `a_state_write_built_as_the_worker_builds_it_lands_for_a_live_run` | FAIL / PASS restored |
| guest connection text | `ConnectionFailed` arm removed from `guest_reply` | `a_fence_failure_reaches_the_guest_as_one_sentence` | FAIL / PASS restored |
| statement recorded whatever its outcome | `unrecorded` starts `None` | `a_refused_or_failed_statement_is_recorded_too` | FAIL / PASS restored |
| not parsed without a slot | handler called before `admit` | `a_message_is_not_parsed_without_an_admission_slot` | FAIL / PASS restored |

## Deliberately NOT done

- No migration of existing `execution_state` rows: every row written before
  this package was keyed on a job id and has been, or will be, orphan-swept.
- Argument-shape refusals are recorded `refused` with the page the caller
  asked for (or 1); the record does not distinguish a gate refusal from a
  malformed `page_size`. The text of the refusal is not stored.
- The two live-service tests newly named (replay guard, NATS call site) are
  named, not changed. Both pass against a throwaway `redis:7-alpine` and
  `nats:2.10-alpine -js`, the images the runner starts.

## Stated limits

- A module-bound dispatch's `state` calls are in-memory only, as they were in
  effect (refused) before.
- The leg is a substring heuristic over text; a test reached through a
  `#[path]` module or a macro-generated name may need a marker.
