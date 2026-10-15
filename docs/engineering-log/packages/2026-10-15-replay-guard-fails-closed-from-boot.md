# The replay guard fails closed from boot, in every deployment shape (2026-10-15)

Security review 2026-10-15 (round 2), findings **B2-2** (Medium), **H2-1**,
**B2-3**, **B2-4** (Low), **B2-8**, **B2-9**, **H2-5** (Info). Package R2 of
the round-2 remediation. Stacked on R1 (#1316): both touch
`talos-rpc-subscribers/src/kernel.rs` and `lib.rs`.

## The defects, as verified

- **B2-2.** `TALOS_REPLAY_FAIL_CLOSED` was consulted only inside
  `talos_replay_guard::admit`, i.e. only when a guard was registered. The
  controller (`register_distributed_replay_guard`) and the worker
  (`register_dispatch_replay_guard`) registered a guard only when the first
  Redis connect succeeded; on failure — or with `REDIS_URL` unset — they
  logged and continued, and `crossreplica_replay_ok` / `first_use_fleet_wide`
  answered `true` for `None`. A process that booted during a Redis outage ran
  for its lifetime with no fleet-wide replay check and no refusal.
- **H2-1.** `docker-compose.prod.yml` set no `TALOS_DISTRIBUTED_REPLAY` and no
  `TALOS_REPLAY_FAIL_CLOSED`; under its `RUST_ENV=staging` the fail policy
  defaults open. **Found while building the parity leg, beyond the review:**
  the same file also set neither `TALOS_WRITE_CEILING_ENFORCED` (controller
  and worker) nor `TALOS_RLS_SET_ROLE` (controller), both of which the chart
  sets and the code defaults OFF (`write_ceiling_gate.rs:89`,
  `talos-worker-runtime/src/context.rs:1349`, `talos-db/src/lib.rs:28`). Used
  on its own, as its header says (`docker compose -f docker-compose.prod.yml
  up`), that stack ran with the actor write ceiling unenforced on both sides
  and without row security's per-transaction role. Used as an overlay on
  `docker-compose.yml`, as `docs/deployment.md` says, the dev file supplied
  them — and also `TALOS_REPLAY_FAIL_CLOSED=false`. Severity on the
  standalone shape: Medium (a documented control off on a user-facing
  deployment).
- **B2-3.** A verified dispatch the worker refused (replay, or store
  unavailable under fail-closed) was a WARN and a dropped permit: no metric,
  no reply; the two causes shared one message. The claim responder's drops
  were one WARN per 1 024.
- **B2-4.** The 2 s admission wait (#1304) parks the intake loop; while it
  waits the loop does not read the subscription, and async-nats' channel
  (65 536 messages by default, measured in `async-nats-0.47.0/src/options.rs`)
  fills with payloads of up to `MAX_WIRE_BYTES`.
- **B2-8.** `TALOS_ALLOW_LEGACY_FLEET_HMAC=1|true|yes|on` acknowledged all
  three surfaces.
- **B2-9.** The guard's per-call failure log said "falling back to per-replica
  replay protection" while a fail-closed caller refused.
- **H2-5.** `values.yaml` did not mention `TALOS_ALLOW_LEGACY_FLEET_HMAC`.

## Decided

- **Operator decision D2-B: register-and-refuse (built).** With
  `TALOS_DISTRIBUTED_REPLAY` on, both processes register the guard whether or
  not Redis answers at boot (`RedisReplayGuard::registering`). A guard with no
  connection answers `Unavailable` and tries to connect again at most once
  per `RECONNECT_EVERY` (1 s), so the first call after Redis returns connects.
  The alternative — refuse boot without Redis — was not built: it takes a
  single-replica dev stack down with its Redis, and the guard that refuses
  until Redis answers gives the same protection while the process is up.
- **One decision for every caller, `talos_replay_guard::ReplayPolicy::decide`**
  (controller RPCs, worker dispatch, the Jira receiver's shared check): a
  replay refuses; `Unavailable` refuses when failing closed; and NO guard is
  treated as `Unavailable` when the switch says there should be one. With the
  switch off, no guard admits — the process-local caches are the configured
  defence, as before.
- **Deviation from the prompt, stated:** the prompt says the no-guard arm
  refuses "when `is_production()` and the switch is on". The policy refuses
  when the switch is on and the process fails closed, with no separate
  production test: `fail_closed_from_env` already defaults to
  `is_production()`, so the production behaviour is the prompt's, and an
  operator who sets `TALOS_REPLAY_FAIL_CLOSED=1` outside production gets what
  the setting says rather than a silent admit.
- **`TALOS_DISTRIBUTED_REPLAY` is read in one place**
  (`talos_replay_guard::distributed_replay_from_env`); the controller and the
  worker each read it by name before.
- **A refusal for want of the store is answered; a replay never is.** The
  worker answers a verified dispatch refused `StoreUnavailable` on its signed
  reply topic (or the results subject, as every result) with a signed
  `Failed` whose error is `talos_reason_class::dispatch::REPLAY_STORE_UNAVAILABLE_MESSAGE`
  (`[reason_class=replay-store-unavailable]`). `talos_retry_intelligence`
  classifies it `replay_store_unavailable`, transient: the dispatcher re-sends
  under a fresh nonce after its backoff instead of waiting out the attempt
  window, and the re-send runs once Redis answers. The marker is hoisted with
  the other host markers, so no prose rule reads it first. A replay is not
  answered: the reply topic is the original dispatcher's, which may be waiting
  on the live attempt.
- **Counted:** `talos_worker_dispatch_refused_total{reason="replay"|"store_unavailable"}`
  (worker, pre-seeded at boot beside `rejected_jobs::seed`) and
  `talos_envelope_claims_dropped_total{reason="too_large"|"saturated"}`
  (controller registry, pre-seeded; one increment site,
  `talos_metrics::record_claim_dropped`). Both label sets are closed and
  compile-time.
- **B2-4: stop waiting after a run of sheds**, not a smaller subscription
  capacity. `kernel::AdmissionPacer`: a message waits `ADMISSION_WAIT` (2 s)
  for a slot; after `ADMISSION_SHEDS_BEFORE_DRAIN` (3) sheds in a row the loop
  sheds without waiting — parse-free, as before #1304 — until one message is
  admitted. A flood therefore holds the subscription for at most 6 s of inflow
  per episode; a burst (waits that end in admission) keeps the wait. The
  controller's one NATS client also carries the dispatcher's reply inboxes and
  the results subjects; a smaller `subscription_capacity` there turns a busy
  minute into slow-consumer drops of run answers, so it was not changed. The
  bound recorded: the channel stays count-bounded (65 536), and the loop now
  drains it at parse-free speed after 6 s of a flood.
- **B2-8: a boolean is refused**, with a message saying it is a boolean and
  naming the spellings; `all` stays the way to acknowledge every surface. The
  installer already renders surface names only (`worker-trust.sh`).
- **H2-1: switch parity is a lint leg**, `check-deploy-posture.py` rule 7,
  enumerated from the chart's own `controller.env` / `worker.env`: every
  `TALOS_*` key with a non-empty value must be set on the same service in
  `docker-compose.prod.yml`, a boolean with the same truth value. Exempt by
  name with its reason: `TALOS_DISABLE_POOLING` (wasmtime's pooling
  allocator, a memory-layout choice for pod limits). Stated in addition,
  because the compose file runs `RUST_ENV=staging`: `TALOS_REPLAY_FAIL_CLOSED`
  must be set true. The compose file now sets all of them.

## Measured

Chart vs `docker-compose.prod.yml` `TALOS_*` keys on the pristine tree
(96d86205): the chart's two env blocks set 5 switches the compose file did not
(`TALOS_DISTRIBUTED_REPLAY` ×2 services, `TALOS_WRITE_CEILING_ENFORCED` ×2,
`TALOS_RLS_SET_ROLE`, plus the exempted `TALOS_DISABLE_POOLING`); rule 7 on
the pristine tree reports 7 lines (the 5 switches per service plus
`TALOS_REPLAY_FAIL_CLOSED` ×2), 0 false positives. The three empty chart keys
(`TALOS_AOT_HMAC_KEY`, `TALOS_AUDIT_SIGNING_KEY`,
`TALOS_WORKER_REGISTRATION_TOKEN`) are secret placeholders outside the two env
blocks and are not read.

## Tests

- `talos-replay-guard`: `a_missing_guard_in_production_refuses_when_failing_closed`
  (the policy over every outcome and no guard), `a_guard_registered_while_redis_is_down_answers_unavailable`
  (a real client against a closed port), `a_guard_registered_while_redis_answers_is_connected`
  (live Redis, `lib` item).
- `talos-rpc-subscribers`: `crossreplica_tests::a_missing_guard_in_production_refuses_when_failing_closed`
  (the controller's own entry point, policy and guard passed in).
- `worker`: `dispatch_replay::tests::a_missing_guard_in_production_refuses_when_failing_closed`,
  `…::a_refused_dispatch_is_counted_by_reason`,
  `…::the_store_unavailable_answer_carries_its_marker`, and the two B-5 tests
  rewritten over the verdict.
- `talos-retry-intelligence`: `a_dispatch_refused_for_want_of_the_replay_store_is_retried`
  (the worker's exact message, the production classifier).
- `talos-metrics`: `envelope_claim_drops_are_seeded_by_reason`.
- `talos-security-audit`: `the_replay_guard_is_reported_from_its_own_state`.
- `kernel::intake_tests::a_run_of_sheds_stops_the_wait_until_a_message_is_admitted`
  (pins both constants).
- `talos-config`: `the_acknowledgement_is_parsed_strictly` (booleans refused).
- `check-deploy-posture.py --self-test` (rule 7: a missing switch, a switch
  stated the other way, the staging-stated switch, a switch new to the chart,
  a missing env block).

## Mutation proof

| Gate | Mutation | Test | Verdict |
|---|---|---|---|
| no guard refuses when failing closed | `decide`: no guard is never "meant to vouch" (`outcome.is_some()` only) | `talos-replay-guard` / `talos-rpc-subscribers` (`crossreplica_tests`) / `worker` (`dispatch_replay::tests`) `a_missing_guard_in_production_refuses_when_failing_closed` | FAIL ×3 / PASS ×3 restored |
| a boolean acknowledges nothing | `"1" \| "true" \| "yes" \| "on"` folded back into the `all` arm | `fleet_identity::tests::the_acknowledgement_is_parsed_strictly` | FAIL / PASS restored |
| chart/compose switch parity | rule 7 removed from `RULES` | `check-deploy-posture.py --self-test` | FAIL / PASS restored |

## Deliberately NOT done

- No boot refusal without Redis (D2-B's other option), as above.
- `TALOS_DISTRIBUTED_REPLAY` is not required in production; with it off the
  `replay_guard` audit entry is a `warn` in production.
- The dev `docker-compose.yml` keeps `TALOS_REPLAY_FAIL_CLOSED=false`
  (a laptop's Redis restarting should not stop the stack); rule 7 reads only
  the production compose file.
- The worker's refusal reply is not driven end to end in a test (it is in
  `main.rs`'s job loop); the message, its classification and the verdict that
  selects it are.

## Stated limits

- During a Redis outage under fail-closed, a replay of a dispatch whose
  original is still running elsewhere is answered `Failed` (the worker cannot
  tell it from a first sighting) and the dispatcher re-sends; the original's
  answer is then for an attempt the dispatcher no longer waits on.
- A worker started with no Redis and the switch on refuses every dispatch
  when failing closed; that is the policy, said once at boot at ERROR.
