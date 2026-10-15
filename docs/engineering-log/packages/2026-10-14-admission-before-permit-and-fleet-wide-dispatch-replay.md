# Admission is bounded before the parse, and a dispatch runs once per fleet (2026-10-14)

Security review 2026-10-14, findings **B-5** and **B-6** (Medium). Package 5c
of the review's remediation.

## The defects, as verified

- **B-6.** `kernel::spawn_rpc_subscriber` spawned one task per inbound
  message with nothing in front of it; each task parsed the JSON, verified
  the signature and asked the shared replay store before it reached the
  per-subject execution permit. A flood grew the `JoinSet` with the inbound
  rate. The claim responder (`talos-envelope-seal`) spawned a bare
  `tokio::spawn` per `SecretClaim`, with no bound at all.
- **B-5.** A worker's only replay defence for a `JobRequest` was its
  process-local nonce cache. Workers share a queue group, so a captured,
  still-fresh dispatch re-published on `talos.jobs` reached a worker that had
  not seen its nonce and ran again. The idempotency cache covers only a job
  that already succeeded on that worker or in Redis.

## Corrections to the review

- "NATS server `max_payload` was not found pinned in `deploy/`": it is pinned
  at 8 MiB in `deploy/nats/nats.conf` and the chart's NATS ConfigMap, since
  2026-05-18 (#800 moved it with the worker credential). The "32 MB-cap
  payloads" in the scenario are 8 MiB.
- "floods `talos.database.query` … each one costs … a full sqlparser parse
  plus a `write_ceiling` row read" without a key: the controller-side
  sqlparser parse and the ceiling read run only after `admit_from_bytes`, i.e.
  after the signature verified. A keyless flood costs a JSON parse, a MAC and
  (for a verifying message only) a store round trip. The unbounded task
  growth and the pre-permit parse are real.
- "the claim responder has no … `spawn_supervised`": the responder LOOP runs
  under `spawn_supervised(BackgroundTask::EnvelopeSealClaimResponder)`
  (`talos-engine/src/nats_run.rs`); its per-claim tasks were the bare spawns.

## Decided

- **A raw wire cap per protocol, before the parse (B-6).**
  `AdmittableRpc::MAX_WIRE_BYTES`, checked first in `admit_from_bytes`; a
  larger payload is `Malformed` without a JSON parse, a MAC or a store round
  trip. Each cap is `admission::wire_cap(content)` = the protocol's own
  content limits at the worst-case JSON string escape (6×) plus 64 KiB of
  envelope, so no legitimate request reaches it; all seven are below the
  broker's 8 MiB (pinned by `every_wire_cap_sits_between_its_content_and_the_broker_limit`).
  The integration-state value limit, a literal until now, is named
  `talos_integration_state::MAX_VALUE_BYTES`.
- **An admission allowance in front of everything (B-6).** `kernel::intake`
  takes one of `max_in_flight × ADMISSION_PER_PERMIT` (8) slots before the
  handler is even called and holds it for the message's whole life; with none
  free the message is dropped unread and counted as the new `shed` outcome
  (`RpcOutcome::Shed`, class `Finding`; every subject's seeded set gains it,
  66 → 73 pairs), with a WARN at most once per 10 s. The execution permit is
  NOT moved: the kernel's documented reason (an unauthenticated flood must not
  hold execution permits, and `queue_ms`/`exec_ms` keep their meaning) still
  holds. Shedding rather than awaiting a slot: awaiting would park messages in
  the NATS client's subscription buffer, which is bounded in count, not bytes.
- **The claim responder** reads a claim only when it is at most
  `MAX_CLAIM_BYTES` (16 KiB) and one of `MAX_CLAIMS_IN_FLIGHT` (64) slots is
  free; per-claim tasks live in a `JoinSet` reaped by the loop.
- **A dispatch runs once per fleet (B-5).** `worker/src/dispatch_replay.rs`:
  the worker registers the controller's own `RedisReplayGuard` (prefix
  `talos:jobnonce:`) under the controller's switch (`TALOS_DISTRIBUTED_REPLAY`,
  now in the chart's and compose's worker env) and fail policy
  (`TALOS_REPLAY_FAIL_CLOSED`, closed in production). After the request's
  signature pre-check and before the idempotency cache or execution, the
  dispatch's `(job_id, job_nonce)` — `pipeline` keys apart — must be new to
  the fleet. No honest path re-sends a nonce (every controller re-send is
  re-signed). A refused dispatch is dropped WITHOUT a reply: its reply topic
  is the original dispatcher's, which may be waiting on the live attempt.

## One home

- Wire caps: `AdmittableRpc::MAX_WIRE_BYTES` via `admission::wire_cap`.
- Admission allowance: `kernel::intake`.
- Claim intake: `talos_envelope_seal::responder::claim_intake`.
- Fleet-wide dispatch single use: `worker::dispatch_replay::first_use_fleet_wide`.

## Mutation proof

| Gate | Mutation | Test | Verdict |
|---|---|---|---|
| raw wire cap | check disabled | `admission_tests::an_oversized_payload_is_refused_before_it_is_parsed` | FAIL / PASS restored |
| admission allowance | slot never asked for | `intake_tests::{a_message_is_not_parsed_without_an_admission_slot, an_admitted_message_holds_its_slot_until_its_handler_ends}` | FAIL / PASS restored |
| claim size cap | cap ×1000 | `responder::tests::a_claim_is_read_only_within_its_size_and_the_responders_slots` | FAIL / PASS restored |
| dispatch once per fleet | guard answer ignored | `dispatch_replay::tests::{a_replayed_dispatch_runs_once_across_two_workers, an_unreachable_store_refuses_only_when_failing_closed}` | FAIL / PASS restored |

## Deliberately NOT done

- **Caching FAILED results** (the review's second suggestion for B-5): the
  dispatcher's application-failure retry re-sends a failed job under the same
  `job_id` and a fresh nonce and must re-run; caching failures is the
  2026-09-10 defect (the retry budget spent re-reading one cached failure).
  The fleet-wide nonce guard covers the replay of a failed or in-flight job
  instead.
- The worker's call sites in `worker/src/main.rs`'s job loop are not
  mutation-proven; the rule they call is. The two-worker test models the
  shared store in-process; a live two-process Redis test was not written.
- No new NATS `max_payload` (already pinned).

## Stated limits

- With `TALOS_DISTRIBUTED_REPLAY` off, or no Redis, the worker's defence is
  its own process cache, as before; the worker WARNs at boot.
- In production an unreachable Redis now refuses every dispatch on the worker
  (fail closed), as it already refused the controller's RPCs.
- A shed request/reply RPC gets no answer; the calling module sees its own
  timeout.
- Deploy order: none. The worker's key namespace is its own; the controller
  is unchanged for dispatch.

## Follow-up: a burst waits, a flood is shed (2026-10-14, same day)

The admission slot was asked for once (`try_acquire`), so a burst past
`max_in_flight × ADMISSION_PER_PERMIT` on a slow runner shed legitimate
messages. For the fire-and-forget `talos.state.write` that is a lost durability
write, not a retried call; `kernel_two_replica_tests::a_fire_and_forget_message_executes_once`
failed this way in CI (#1303, shard 2) while passing on `main`'s run, which is
what a timing-dependent loss looks like.

`kernel::admit` now waits up to `ADMISSION_WAIT` (2 s) for a slot to free
before it sheds; slots free as handlers finish, and the NATS client buffers
what follows while the loop waits. Only a backlog that does not drain within
the window is shed. The handler is still called — and the message parsed —
only with a slot in hand (`admit` then `spawn_admitted`).

- Test: `intake_tests::a_message_waits_for_a_slot_that_frees_within_the_window`.
- Mutation: the wait removed (one `try_acquire`) → that test FAIL; restored → PASS.
- `kernel_two_replica_tests` pass three runs in a row against a broker.
- Stated limit: while the loop waits it does not observe shutdown; the wait is
  2 s against a 10 s drain deadline.

## Correction, 2026-10-15 (security review round 2, B2-7)

The mutation table above names
`intake_tests::a_message_is_not_parsed_without_an_admission_slot`; the
follow-up that added the wait replaced it, so from then until 2026-10-15 the
"not parsed without a slot" property was held only by the loop's shape. The
loop's step is now one function, `kernel::intake`, and the named test is
restored against it (the handler is not called without a slot, is called once
with one, and the slot is returned). Mutation: the handler called before
`admit` → that test FAIL; restored → PASS. See
`2026-10-15-state-write-names-the-run.md`.
