# A job result is counted once, and answers the attempt it names (2026-10-14)

Security review 2026-10-14, findings **B-1** (Medium) and **B-9** (Low).
Package 5b of the review's remediation. Two PRs: this one (protocol,
controller, migration) and a stacked one in which the worker starts stamping
results, for the deploy reason under "Decided".

## The defects, as verified

- **B-1.** `talos-job-result-observer` is the only consumer of
  `talos.results.*` — the subject a worker publishes to when a dispatch has no
  reply inbox (Gmail / Calendar / GCP push, webhook DLQ replay). It verified
  with `verify_no_replay_dispatch`, the observer flavour, on the stated belief
  that its writes were idempotent. The status write is (`WHERE status IN
  ('pending','running')`); the fuel write was not: `RECORD_MODULE_BOUND_FUEL_SQL`
  added to `module_executions.fuel_consumed` and inserted a rollup row for
  every copy. One captured result republished inside its 300 s window drained
  the actor's hourly fuel budget. Its module comment ("mostly dormant") was
  stale; push dispatch uses this path.
- **B-9.** `JobResult`'s signed payload named no attempt and no execution
  (`JobProgress` names its attempt). A retry keeps the `job_id` and the reply
  inbox, and the dispatcher compared only the `job_id`, so a slow attempt's
  result arriving during the next attempt was taken as that attempt's.
- Found while verifying: the webhook router's request/reply path compared
  nothing at all — not even the `job_id` — before taking a signed result as
  the webhook's response.

## Decided

- **The observer is the primary verifier** for module-bound results
  (`verify_dispatch`, which records the nonce). Nothing else in the controller
  subscribes to `talos.results.*`, and the worker publishes a result to the
  reply inbox XOR that subject, so this is the one primary per process.
- **Fuel once per signed result, in the database.** The replay cache is per
  replica and the observer is in a queue group: a copy delivered to another
  replica passes there. Migration `20261014180000` adds
  `execution_cost_rollup.result_nonce` with a partial unique index on
  `(execution_id, result_nonce)`; `record_module_bound_fuel` inserts the rollup
  row with `ON CONFLICT DO NOTHING` and adds to `fuel_consumed` only when it
  inserted (`ModuleBoundFuelRecord::{Recorded, AlreadyRecorded, NoRow}`). The
  webhook router passes its result's nonce too. Workflow dispatch rows keep
  `NULL`: their result is verified once by the one dispatcher holding the
  inbox.
- **A result names its dispatch (B-9).** `JobResult` gains `dispatch_attempt`
  and `workflow_execution_id`, signed with the conditional-append idiom after
  `:fuel=` (`:attempt=<n>` when non-zero, `:exec=<uuid>` when present); an
  unbound result signs the pre-field bytes. `JobResult::bind_to_request` stamps
  them; `JobResult::answers(&DispatchIdentity)` is the one rule:
  `ThisDispatch`, `Unbound` (no execution named: a worker that predates the
  binding — taken as before), `EarlierAttempt`, `Mismatch` (another job,
  another execution, or an attempt never sent).
- **The dispatcher refuses what is not this attempt's answer**, read against
  the request the live attempt actually sent (`current_payload`, so a failed
  re-sign is matched against what went out). Refusing a slow attempt's result
  outright would have turned "the next attempt is still running" into a node
  failure, so the reply wait drops it instead: `JobTransport::request_with_reply_inbox_and_progress`
  takes a `skip_reply` predicate, the NATS transport drops a reply it names and
  keeps waiting, and the dispatcher passes `is_earlier_attempt_reply` (a
  `true` only ever drops a message; nothing is accepted on unverified bytes).
  One that reaches the dispatcher anyway is refused.
- **The webhook router asks `answers` too**, before verifying.
- **Deploy order: this PR before the worker PR.** A worker that stamps the
  binding signs bytes an older controller does not compute, so every result
  from it would be refused. A controller from this PR verifies results with or
  without the binding; the worker change is the stacked PR, exactly as the
  2026-09-29 out-of-band fuel field was split.

## One home

- What a result answers: `talos_workflow_job_protocol::JobResult::answers`.
- Stamping: `JobResult::bind_to_request`.
- Module-bound fuel, once: `talos_cost_attribution::record_module_bound_fuel`.
- Dropping an earlier attempt's reply: `talos_workflow_engine_nats::attempt_wait::is_earlier_attempt_reply`.

## Mutation proof

| Gate | Mutation | Test | Verdict |
|---|---|---|---|
| observer is primary | `verify_dispatch` → `verify_no_replay_dispatch` | `job_result_observer_tests::a_repeated_delivery_of_one_result_is_refused_and_counts_no_fuel` | FAIL / PASS restored |
| fuel once per result | `NULLIF($6,'')` → `NULL::text` | `fuel_ledger_tests::a_module_bound_results_fuel_is_recorded_once_per_signed_result` | FAIL / PASS restored |
| dispatcher refuses an earlier attempt | `EarlierAttempt` admitted | `an_earlier_attempts_result_that_reaches_the_dispatcher_is_refused` | FAIL / PASS restored |
| inbox drops an earlier attempt | predicate matches `Mismatch` instead | `a_slow_attempts_result_is_not_taken_as_the_next_attempts` | FAIL / PASS restored |
| binding is signed | `:exec=` segment not appended | `result_binding_tests::the_binding_is_signed_and_a_bound_result_still_verifies` | FAIL / PASS restored |

Wire snapshots: `an_unbound_job_result_signs_the_pre_binding_bytes` (all
default: the hand-rolled pre-field payload's MAC verifies under production
`verify`) and `job_result_non_default_dispatch_binding_snapshot` (its own JSON
and MAC hex), plus `a_results_dispatch_binding_cannot_be_stripped_or_moved`.

## Deliberately NOT done

- The router's `answers` check is not mutation-proven at the call site: its
  reply path has no harness short of a live broker. The rule it calls is.
- `PipelineJobResult` is not bound: chain dispatch is disabled, and its steps
  are not retried under a shared inbox in the same way.
- An `Unbound` result is accepted for every attempt during the rollout.
  Requiring the binding (refusing `Unbound`) is a later flip once the fleet
  runs the stamping worker; it is not built here.

## Stated limits

- A slow attempt's result dropped at the inbox is not recorded: its fuel and
  LLM usage are not counted (as before, when the later attempt's result was
  the one dropped).
- The worker's idempotency cache re-serves a cached result under a fresh
  signature (stacked PR); its fuel is the cached run's, counted when that
  re-serve is the answer accepted.

## The worker PR (stacked)

- Every result the worker signs for a request goes through
  `sign_job_result_for` (`worker/src/main.rs`), which stamps the request's
  attempt and execution (`bind_to_request`) and signs. The oversized-result
  replacement copies the original's binding; the idempotency cache re-binds a
  cached result to the request it now answers and re-signs it (fresh nonce).
- Mutation: the stamp removed from `sign_job_result_for` →
  `a_signed_result_answers_the_request_it_was_signed_for` FAIL / PASS restored.
- Deploy only after a controller carrying the first PR is running.
