<!-- Archived narrative, moved VERBATIM out of CLAUDE.md. Do not reword: the
     digest in CLAUDE.md's "Engineering log" section points here, and
     `scripts/check-engineering-log.py` proves every removed line still
     appears here. New decisions go in CLAUDE.md first. -->

## A re-dispatched job is a second chain, and the wire says so

**`JobRequest.dispatch_attempt` — the partition key a credential-free worker
cannot derive.** #769 fixed the in-WORKER retry (one ledger per job). The
remainder it recorded is the CONTROLLER re-dispatching the same `job_id`: each
re-dispatch is a fresh worker job with a fresh ledger, so two dispatches write
two chains that both start at `sequence_num` 1 against the same genesis, under
one S3 prefix. `verify_chain` sorted by `sequence_num` alone and had no key to
tell them apart, so it reported `DuplicateSequence` — positive tamper evidence,
ERROR, `talos_audit_verification_failures_total{stage="chain"}` — every time a
controller retry followed a completed-but-unanswered attempt. A worker with no
credentials cannot know it is a re-dispatch unless the controller tells it.

**Measured on the live bucket 2026-09-07** (49,863 objects / 49,604 prefixes):
**150 prefixes hold more than one object** (111×2, 23×3, 5×4, 3×5, 1×7, 1×8,
1×10, 2×11, 3×12) plus **41 single-object prefixes at 960 B under a `1_1_` key**
(two seq-1 events in one object), i.e. ~191, consistent with #769's 196. The
largest are provably controller retries, not in-worker ones: the 12-object
prefix's `workflow_executions` row carries `node_started` + **two
`node_retrying`** + `node_failed`, i.e. **3 controller dispatches × 4 in-worker
attempts = exactly 12 objects**, and 11–12 copies exceed the worker's own
`RetryPolicy::default().max_attempts = 3` ceiling. Rate: ~1,300
`module_executions`/day against 0–4 `node_retrying` events/day.

**#769's mechanism sentence was wrong and the correction matters**: this is not
"after a timeout". `execute_job_with_retry`'s `Err(_timeout)` arm RETURNS; the
two arms that loop are an application-level failure and a NATS delivery/reply
error. A reader sent to the timeout branch finds nothing.

**The design.** `JobRequest.dispatch_attempt: u32`, `#[serde(default,
skip_serializing_if)]`, appended to `signing_payload` as `:attempt=<n>` ONLY when
non-zero and at the very END — so an all-default request is byte-identical on the
wire AND in its MAC (pinned by the unchanged
`job_request_signature_snapshot` hex plus a NEW non-default snapshot with its own
JSON + MAC). `AuditEvent.dispatch_attempt` follows the same idiom into
`calculate_hash`, so an attempt-0 event's hash and HMAC are byte-for-byte what
they were and **every object already in the bucket keeps verifying** —
`attempt_zero_event_hash_and_hmac_are_pinned` locks the literals, and the formula
was additionally re-derived by an INDEPENDENT Python implementation against a real
bucket object (stored `hash` and `previous_hash` both reproduced exactly), because
a fixture that pins the code against the code cannot see a both-sides drift.
`verify_chain` PARTITIONS by attempt and verifies each partition as its own chain
**from the same genesis** — the attempt is a partition key, NEVER a genesis
input, so an old chain and a new one are verified by one rule — and
`verify_chain_anchored` partitions its anchor verdict the same way (two attempts
carry two terminal anchors, which as one set read `MultipleAnchors`, a HARD
failure, on a retried job). Within one attempt `DuplicateDelivery` and
`DuplicateSequence` keep #769's meanings exactly; the CONTROL test proves a
conflicting pair at ONE attempt still fails.

**ONE stamping site, and that is structural rather than tidy.**
`resign_payload_for_retry` sets the attempt before signing. Both call sites sit
inside `if let Some(key) = worker_shared_key`, so a deployment with no WSK
re-sends the ORIGINAL bytes — and that path **cannot produce a second chain at
all**: `req.verify_dispatch` (nonce-replay included) runs in the worker ABOVE the
ledger, so a replayed nonce fails before `execute_job_with_full_features` is
reached. Every path that can write a second chain re-signs, and that is exactly
the path that stamps.

**Deploy ordering — measured in both directions, and the two are NOT symmetric.
WORKERS ROLL FIRST OR TOGETHER**, the same rule the envelope-seal note carries,
and the first draft of this paragraph got it backwards before the test was
written. **Old controller + new workers is completely inert**: nothing stamps
anything, every message is attempt 0, every byte identical. **New controller +
old workers is safe for FIRST dispatches and refuses RETRIES.** Attempt 0 appends
nothing, so an ordinary dispatch is byte-identical and an old worker verifies it
exactly as before. A RETRY, though, is signed by the new controller over a
payload ending `:attempt=1`, and an old worker's `signing_payload` cannot produce
that segment — it does not know the field — so the two MACs differ and the old
worker REFUSES the retry. Pinned by
`an_old_worker_refuses_a_new_controllers_retry_but_accepts_its_first_dispatch`,
which rebuilds the pre-field payload and asserts the signatures diverge (if they
matched, binding the attempt would be a no-op). This is **fail-CLOSED and
bounded**: the failure is a refused retry of an already-failing job, not a
mis-verified one, and it lasts only for the width of the rollout — measured
0–4 `node_retrying` events/day on the reference fleet. Roll workers first and it
never arises.

**Disclosed, never silent.** The sweep counts `ChainSweepStats::multi_attempt`
and logs `jobs_with_multiple_attempts`; `security_audit`'s round-trip check names
the attempt count on the chain it probed (because "4 events, verified" and "two
dispatches of two" otherwise render identically — the same argument the
`duplicate_deliveries` disclosure makes one axis over) and the sweep note carries
the fleet count; the GraphQL job report gains `dispatchAttempts` and the
aggregate `jobsWithMultipleAttempts`; `talos_audit_chain_multi_attempt_jobs_total`
is pre-seeded at 0. **Nothing alerts on it** — a re-dispatch is the platform
working as designed, and an alert here would train operators to ignore the one
control that raises a true finding, which is the defect this change removes.

**What is NOT closed, stated rather than implied.** (a) **Historical prefixes
stay CONFLICTING.** Both copies carry no attempt field, so they partition into
ONE attempt and `DuplicateSequence` is the correct answer for them — the fix is
forward-only. They age out of the sweep's 2 h window; the ~191 already in the
bucket are reachable only by an on-demand `verifyAuditChain`. (b)
**`PipelineJobRequest` is deliberately unchanged.** The chain path CAN re-dispatch
(`dispatch_with_retry` loops on a transport error), but it writes NO audit chain
at all: the only non-test `ExecutionLedger::new` is in
`execute_job_with_full_features` and the only `set_audit_ledger` is on the
single-node path, so `execute_pipeline` mints neither — and every production
entry point passes `ChainDispatch::Disabled` besides. A `dispatch_attempt` there
would partition nothing that exists. (c) **The partition is only as good as the
stamp reaching the worker.** No test in this workspace can drive
controller-dispatch → NATS → worker → S3 end to end; the guard is the live read
of the ledger after deploy, the position #767 and #769 both took about their own
changes.

**No lint check was added and `--count` stays 86.** Two candidates were measured
first and both have a population of ONE, the bar this repo does not ship at. (i)
*"a conditional-append signing segment must have a non-default wire snapshot"* —
`signing_payload` holds FOUR conditional segments (`:egress=`, the sealing block,
`:idem=`, `:attempt=`) and exactly ONE has a non-default snapshot (the one added
here), so the check would ship at 3 and the repo does not re-add baselines
(check 52's own rule). (ii) *"`ExecutionLedger::new_for_attempt` must be the
producer's constructor"* — `ExecutionLedger::new*` occurs ONCE in non-test worker
code, which is the same population #769 measured and rejected for the same
reason. The structural answers are stronger than a grep in both cases: the
snapshot pair is in the same file with a docstring saying why there are two, and
the ledger has one construction site the compiler funnels every caller through.

**Instruments, and deliberately no alert.** Both counters are PRE-SEEDED
(`talos_audit_ledger_duplicate_deliveries_total{scope="batch"}` — the only scope
with a live increment site, because the writer cannot see a cross-batch copy —
and `talos_audit_chain_duplicate_deliveries_total`). NOTHING alerts on either:
at-least-once delivery is the transport working as designed, and an alert here
would be the same train-the-operator-to-ignore-it defect the classification
removes. `TalosAuditVerificationFailures` was REVIEWED and left unchanged
because the change made it strictly MORE selective — a duplicate delivery now
touches no series it selects — with two promtool cases pinning both directions
(duplicates climbing fires nothing; a real break still pages while they climb).
The sweep reports `jobs_with_duplicate_delivery` beside the verdict and never
inside `failed`; `security_audit`'s `audit_chain_verification` renders a
duplicate-only chain as PASS with the count DISCLOSED, because "2 events,
verified" and "1 event delivered twice" otherwise render identically. The
GraphQL surface exposes `duplicate_delivery` as a `kind` and a per-job
`duplicateDeliveries` count.

**No lint check was added and the count stays 86.** TWO candidates were
measured first, and both have a population of ONE, which is the bar this repo
does not ship at. (i) *"a `ChainBreak` consumer must branch on
`is_tamper_evidence`, not `breaks.is_empty()`"* — measured workspace-wide,
`breaks.is_empty()`/`breaks.len()` appears at **3 lines and none is a verdict**
(two test assertions and `security_audit`'s Broken-arm count, itself fixed here
to count tamper evidence only); `ok` is computed in exactly ONE place. (ii)
*"the worker runtime may mint an `ExecutionLedger` only above the retry loop"* —
`ExecutionLedger::new` occurs **once** in non-test worker code and
`append_terminal_anchor` **once**. The structural answers are already stronger
than a grep: `ok` has one home, `seal_job_audit_chain` is the one place an
anchor is appended and the labelled block gives it one call site, and the
`From<&ChainBreak>` GraphQL mapping is an EXHAUSTIVE match that FAILED TO
COMPILE until the new variant was classified — which is the guard that a grep
would only imitate.

**The one measured SURVIVOR, stated rather than implied.** Reinstating a
per-attempt `ExecutionLedger` inside
`execute_job_with_context_and_timeout_internal` — i.e. the original defect —
leaves all 639 `talos-worker-runtime` tests green. Nothing in the suite can
observe it: the anchor's only externally visible effect is a NATS publish, and
the retry loop needs a wasmtime engine, a compiled component and a NATS server
to drive. What IS covered is the sealing RULE (`seal_job_audit_chain`'s four
tests, three of which fail under their own mutations) and the classification the
defect used to trip (`verify_chain`'s). The honest guard for the call site is
the live read of the ledger after deploy — the same position #767 took about its
sweep — not a test that does not exist.
