# RFC 0014 — Local inference that does not depend on the schedule

**Status:** In progress — P1 (progress-based deadlines) 2026-09-28; P2a (waiting not charged to the job) 2026-09-28; P2b (nor to the run) 2026-09-28; P2c measured and not built 2026-09-28; P3a (the controller gated and on progress deadlines) 2026-09-28; P3b (one queue across processes) 2026-09-28
**Author:** Platform
**Date:** 2026-09-28

## TL;DR

The goal: any number of workflows may start at the same moment and none of them
fails because the others exist. Today they can, because a local (Ollama) LLM call
has a **fixed 60 s total deadline**, while the backend serves one request at a time
and the platform keeps sending it more work.

Four phases:

1. **P1:** a call is cut when it stops making **progress**, not when a clock runs
   out.
2. **P2:** time spent **waiting** for the backend is not charged to a call's
   deadlines (P2a: the job's; P2b: the run's), and waiting calls are admitted
   fairly and model-aware (P2c — measured, not built).
3. **P3:** admission is **fleet-wide** and covers the controller's own Ollama
   client.
4. **P4:** timeouts are **classified** for retry and made **visible**.

P1 ships with this RFC. It is a Pareto change: no call that completes today can
fail under it.

## Context

### The shape today

- The worker calls Ollama's `/api/chat` with `stream: false` and wraps the whole
  exchange in one `tokio::time::timeout` of `LOCAL_LLM_EXCHANGE_TIMEOUT_SECS`
  = **60 s**.
  - The call covers model load, prompt evaluation and generation.
  - The response is one JSON object, so until the last token is generated nothing
    arrives. A call that is 59 s into a healthy generation is indistinguishable
    from a stuck one.
- `llm_gate` (#792) serializes a worker's local calls (cap 1, FIFO, up to 120 s
  of queue wait) and takes its permit **before** the 60 s starts. So queue time
  inside one worker is not charged to the exchange.
  - It **is** charged to the node's attempt window (default 120 s) and to the
    workflow budget.
  - It does not see other worker replicas or the controller.
- The host Ollama runs `OLLAMA_NUM_PARALLEL=1` and `OLLAMA_KEEP_ALIVE=5m`. It
  alternates between `qwen3.6` (24.8 GiB at the configured
  `OLLAMA_CONTEXT_LENGTH=131072`) and `qwen2.5-coder:14b` (14.4 GiB). Each
  alternation evicts the other model ("predicted to exceed available memory,
  evicting"), and a reload takes 3–8 s.
- The controller's `talos_llm::OllamaClient` has its own 60 s total timeout
  (`OLLAMA_HTTP_TIMEOUT`), in a different process, against the same backend.

### Measured, 2026-08-27 → 2026-09-28 (host Ollama request log, 32 days)

- **33,891** `/api/chat` requests.
  - Of the 33,808 that succeeded: p50 0.5 s, p95 9.1 s, p99 19.9 s, max 138 s.
- **47 requests were cut at 59.7–60.0 s** (the client hung up; Ollama logs 500).
  - That is the worker's or the controller's total deadline firing, not an Ollama
    error.
  - 13 requests over 60 s did complete. Those can only have come from a caller
    whose deadline is longer than 60 s.
- **A 60 s cut between 07:55 and 08:15 on 19 of September's 20 weekday mornings** (every one but 09-03), usually at 08:01. At 08:00 local six
  workflows start together:
  - `pa-chief-of-staff`, the hourly alert-triage workflow, `pa-ask-email`,
    `pa-followup-approval-notifier`, `ops-critical-notifier`, and
    `content-pipeline-weekly` on Mondays.
  - The first local request of the morning is cut at 60 s, almost every day.
  - On most days a caller absorbs the error: the workflow completes and no
    `node_retrying` event is written. **Which caller it is cannot be attributed**
    from what is retained (the worker log does not survive a restart).
- **2026-09-28, the failure that prompted this RFC.** `pa-chief-of-staff`'s
  `synthesize` node (`qwen3.6`, `MAX_TOKENS` 1800, no node timeout so a 120 s
  attempt, workflow budget 420 s) failed after 3 attempts.
  - The Ollama log shows **attempt 1 was the only request in flight** from 07:37
    until it was cut at 08:01:14, and **no model load** happened in that window.
    It was a healthy generation on a loaded model, killed by the clock.
  - Attempt 2 then had to reload `qwen3.6` after the alert-triage workflow's
    `qwen2.5-coder:14b` call evicted it, and was cut at 60 s. So was attempt 3.
  - Each retry re-ran the whole generation and paid for a model swap.
- **Not measurable, stated:** the true service time of the 47 cut calls. Each
  was aborted at 60 s, so how long it would have taken is unknown. P1 does not
  need that number (see its Pareto property). A decision to *raise* the 60 s
  would, and #792 declined exactly that for exactly this reason.

### What is wrong, in one sentence each

1. A **total** deadline cannot tell slow from stuck. It cuts healthy long
   generations and, before P1, gave the operator nothing to tune but the size of
   the clock.
2. **Waiting** is charged to deadlines that are meant to bound work.
3. The only admission control is **per worker process**. Two worker replicas and
   the controller all queue at Ollama itself, where nothing is fair or
   model-aware.
4. A timeout is **retried as if transient** and re-runs the whole generation, so
   retries amplify the queue they were caused by.

## Decisions

### P1 — progress-based deadlines (this PR)

1. **Stream local exchanges.** Local calls from `llm::complete*` and
   `llm-tools::complete-with-tools` send `stream: true` and read Ollama's JSON
   lines.
   - The lines are assembled back into exactly the object the non-streaming API
     returns: concatenated `message.content`, every `message.tool_calls`, and
     `done_reason` / `prompt_eval_count` / `eval_count` from the `done` line.
   - That object is handed to the **unchanged** adapter parser, so the parser
     stays the one source of truth for the wire format.
   - The guest API does not change: guests still get one completion.
2. **Three deadlines replace the one:**

   | Deadline | Value | What it bounds |
   |---|---|---|
   | first byte | 60 s | send + model load + prompt evaluation, until any byte of the answer arrives |
   | idle | 60 s | the gap between any two chunks |
   | ceiling | 600 s | the whole exchange, as a backstop; the node's attempt window is expected to bind first |

   **The Pareto property:** any call that completes within 60 s today received
   its first byte within 60 s and never waited more than 60 s between chunks, so
   it passes the new rule. **No call that succeeds today can fail under P1.**
   - A call that makes progress past 60 s now completes. A stuck call is still
     cut, within 60 s of its last byte.
   - A shorter idle deadline was considered and rejected on this property. Ollama
     emits no chunk while a tool call's text is buffered, so a long tool call can
     go quiet for many seconds, and any idle bound below 60 s could fail a call
     that works today.
   - Thinking-model output (`message.thinking`) counts as progress and is dropped
     from the assembled content, as the non-streaming API does.
3. **Classification is unchanged.**
   - A deadline firing is `LlmFailure::Timeout` / `Error::Timeout`, whichever of
     the three fired. The kind is logged, and deliberately not a label yet (P4).
   - An `{"error": …}` line mid-stream is the provider reporting a failure. It is
     classified `HttpStatus`, exactly as the same failure was when it arrived as
     a non-streaming HTTP 500. The provider's text is never echoed to the guest.
   - A stream that ends without `done` is `Network`.
   - Bytes over `MAX_LLM_BODY_BYTES` are `OversizedResponse`. The streamed wire
     is counted, not the assembled text, so the cap stays a memory bound.
4. **External providers are unchanged** (non-streaming, 120 s total).
   **`llm_streaming` (the guest's own SSE stream) is unchanged.**
5. **The controller's `OllamaClient` is not changed in P1.** It is a different
   process with different callers, and it belongs with P3, which has to touch it
   anyway.

### P2a — waiting is not charged to the job (2026-09-28)

**Measured first.** Over 30 days of the gate's own histogram, 94 % of local calls
waited under 10 ms at the gate, but about 56 waited over 30 s and 9 over 60 s,
every long wait inside a scheduled herd (the 06:00, 07:00 and 08:00 starts). Each
of those waits was charged to the job's deadlines.

1. **The rule, one home.** `talos_workflow_engine_core::inference_wait` —
   `WaitAccounting` and `LOCAL_INFERENCE_WAIT_CREDIT_CAP_SECS` (300 s), shared by
   worker and controller so the two clocks apply one rule and one cap. Deadlines
   measure work; waiting has its own bound.
2. **Worker.** The gate records a wait on the job's `InferenceWaitLedger` only
   when a call actually queues (a free slot is taken silently). All three
   worker-side wall-clock bounds stand still while a wait is open: the outer job
   timeout, the inner `call_async` timeout, and the epoch callback's wall-clock
   bound. The epoch TICK budget is untouched — ticks only burn while the guest
   runs.
3. **Wire.** A new signed message, `JobProgress { job_id, dispatch_attempt,
   state: waiting|admitted, worker_id, nonce }`, signed like `JobResult`
   (worker Ed25519 or fleet HMAC), domain-tagged `progress:` so it can never be
   confused with a result. It goes to `<reply_inbox>.progress`, derived from the
   SIGNED reply topic.
   - **No request field and no rollout order.** A controller that predates P2
     does not subscribe there and the broker drops the messages. (A request flag
     was considered and rejected: it would bind a new segment into every signed
     dispatch, so a new controller would be refused by every old worker during a
     rollout.)
   - Verify-once: the dispatcher is the only consumer and calls `verify_dispatch`;
     `verify_no_replay_dispatch` exists from day one.
4. **Controller.** The dispatcher listens on the progress subject for the length
   of the attempt and pauses the attempt window while a verified `waiting` is
   open. A report is honoured only if it parses, names this job and this attempt,
   verifies, and comes from the first worker that reported for the attempt; any
   other report is ignored and the window runs as before. The window never passes
   the run's deadline less `BUDGET_RESERVE_SECS`, and an unclosed wait is capped.
5. **What a forger gets.** A holder of the fleet key who has seen a job's reply
   inbox can make the controller wait longer for that attempt, by at most 300 s.
   It cannot change a result, skip a gate or extend the worker's own deadlines.

**Not in P2a, stated:** the workflow's own budget still counts queueing (P2b);
pipeline jobs (dormant by config) report nothing; a job whose `waiting` message is
lost is abandoned at its window exactly as before P2.

### P2b — the run's budget pauses too (2026-09-28)

1. **One clock per run, the union of its jobs' waits.**
   `talos_workflow_engine_core::RunWaitClock`, keyed by job id, measured on the
   controller's clock:
   - it pauses while ANY of the run's jobs is queued for the slot;
   - two parallel queued branches pause the run once, not twice;
   - it is capped at the same 300 s as a job.

   A fresh clock is stamped per run beside the deadline.
2. **Every timer that bounds the run reads the LIVE deadline** (stamped deadline
   plus the clock's excluded time):
   - the run-level timeout in `run_with_workflow_timeout`, re-read each time it
     is reached;
   - the dispatcher's per-attempt clamp and the attempt window's upper limit;
   - the inline child window (`bounded_child`) for sub-workflow, judge and
     ensemble nodes.
3. **The dispatcher reports into the run's clock.** Each VERIFIED `waiting` /
   `admitted` for an attempt also moves the run clock (`DispatchJob::run_waits`,
   carried by the single-node and loop-body dispatches). Whenever an attempt
   ends, its wait on the run is closed, so a lost `admitted` cannot hold the
   run open.
4. **Sub-workflows.** A child run's clock forwards to its parent's (carried by
   `AdapterSet`), so a job queued inside `pa-chief-of-staff`'s sub-workflow
   pauses the parent's budget too.

**Stated limits:**
- The child window pauses on the RUN's union, so a sibling branch's queueing
  also holds it. That errs toward more time, and is bounded by the cap.
- Pipeline jobs (dormant) carry no clock.

### P2c — fair, model-aware admission: measured, NOT built (2026-09-28)

**Decided: not built.** It was measured first and would change almost nothing on
this fleet. The numbers come from 30 days of `module_executions` for the 8
modules whose source calls the local LLM (1,445 completed calls), with each
call's model attributed from its workflow node's `MODEL`.

1. **Fair order across runs: no effect.** 0 of 1,445 calls overlapped another
   call from the SAME run; no run ever had two local LLM calls in flight. The
   gate's per-call FIFO is therefore already per-run FIFO. 194 calls (13 %)
   overlapped a call from a DIFFERENT run, and FIFO serves those in arrival
   order as fairness requires.
2. **Model-aware order: negligible effect.** Reordering saves a model swap only
   when three or more calls are in flight with mixed models; with two, the
   second model must load either way.
   - 87 calls had two or more others in flight.
   - 16 of those, on 5 days, involved a known different model.
   - Those counts are an UPPER bound: a module execution's interval contains its
     LLM call and other work.
   - Each such event saves at most one load (3–8 s on this host), so a couple
     of minutes a month. That does not justify an aging scheduler and its
     starvation risk inside the gate.
3. **Where the swaps actually come from:** models used one AFTER another over
   time (`qwen2.5-coder:14b` between `qwen3.6` calls), which no queue order can
   fix. Keeping both models resident does: the `OLLAMA_CONTEXT_LENGTH` operator
   item below.

**Revisit when** a workflow fans out parallel local LLM calls within one run,
worker replicas grow past one (the gate is per process; P3b), or overlapping
mixed-model calls become common. Re-run the same measurement first.

### P3a — the controller's own Ollama client (2026-09-28)

**Measured first** (30 days, the host Ollama's request log joined to the
controller's `llm_usage` rows; `scripts/measurements/rfc0014-controller-ollama-overlap.py`):

- 1 072 controller calls (1 053 matched to a request): p50 2.2 s, p90 6.3 s,
  p99 25.4 s, max 46.3 s — consolidation, reflection, graph-RAG extraction,
  evaluation, the teacher audit and `local_llm_complete`.
- **106 started while another controller call held the backend.** Nothing
  bounded them: `OllamaClient` had no gate.
- **108 worker requests arrived while a controller call held the backend**,
  1 472 s of overlap in total (~14 s each), 3 of them failed; 8 of the 33
  worker requests cut at exactly 60 s overlapped a controller call.
- `OllamaClient` was non-streaming under one 60 s client-wide timeout — P1's
  defect, in the other process. No controller call is RECORDED past 46 s, but a
  failed call writes no `llm_usage` row, so controller calls cut at 60 s cannot
  be counted from here.

**Decided.**

1. **One crate for both processes.** The gate, the streamed exchange, its
   deadlines and the line reader moved from `talos-worker-runtime` into the leaf
   crate `talos-local-inference`; the worker keeps thin re-exports, so its paths
   and behaviour are unchanged. The worker's P2a ledger reporting stays in the
   worker, behind a `QueueWaitObserver` trait the gate is generic over.
2. **The controller takes the gate.** `OllamaClient::chat` — the one method
   every `complete*` call goes through — takes its process's gate before its
   deadlines start, like the worker. Same cap, same env var
   (`TALOS_LOCAL_LLM_MAX_IN_FLIGHT`), same 120 s wait after which a call proceeds
   ungated. It never refuses.
3. **The controller streams, under P1's deadlines.** The request sets
   `stream: true` and is cut on first byte / idle / ceiling; the chunks are
   reassembled into the non-streaming body, so the parse is unchanged. A
   per-request timeout above the ceiling overrides the 60 s client-wide timeout,
   which would otherwise still cut every streamed answer at 60 s total.
4. **Error wording is kept**: an HTTP status still reads
   `Ollama returned HTTP <status>`, which the `think` retry matches on.

**Not done, stated.**

- **The controller and the workers still do not queue against each other.** Each
  process has its own gate, so the 108 controller-vs-worker overlaps are
  unchanged by P3a; that is P3b.
- **`warm_model` is not gated.** It runs once at boot under a task timeout that
  would then count the queue wait; `pull` / `show` / `list` / `delete` are not
  inference.
- **No controller metric.** `talos-llm` has no metrics edge. The gate logs a
  queued call at INFO and an expired wait at WARN; P3b's broker adds series.

### P3b — one queue across processes (2026-09-28)

**Why.** After P3a the controller and each worker still had a gate EACH, so the
backend saw one request per process: the 108 worker requests that arrived while
a controller call held the backend (P3a's measurement) were unchanged.

**Decided.**

1. **A counting semaphore in Redis, keyed per backend** (`talos_local_inference::fleet`):
   holders scored by lease expiry, waiters scored by an `INCR` ticket (FIFO
   across processes), and each waiter's liveness. One Lua script does every
   transition on **Redis's own clock** (`TIME`), so no two hosts' clocks are
   compared. The four keys share a hash tag (one cluster slot) and expire when
   idle. The key is the SHA-256 of the normalised backend URL, so a URL carrying
   credentials never reaches a key name.
2. **Taken after the process gate.** A process has at most `cap` callers in the
   fleet queue; its other calls queue locally with no Redis round trip. One wait
   budget (`LOCAL_LLM_QUEUE_WAIT_SECS`) covers both stages, and a wait at either
   stage is reported once to the worker's P2a ledger, so the job's deadlines
   stand still for a fleet wait too.
3. **One cap.** `TALOS_LOCAL_LLM_MAX_IN_FLIGHT` is the backend's slot count, now
   applied fleet-wide as well as per process.
4. **It never refuses, and Redis is not on the critical path.**
   - Every Redis call is bounded (2 s). A Redis error or a slow call proceeds on
     the process gate (P3a), logged once per outage, not per call.
   - A fleet wait past the cap proceeds ungated, releasing the process permit,
     exactly as an expired process wait does.
   - Leases live 30 s and are renewed every 10 s: a holder that dies frees its
     slot within 30 s. A waiter that gives up leaves the queue at once; one that
     dies leaves within 5 s.
   - A lease that cannot be renewed in time is counted (`lease_lost`); the call
     is not interrupted.
   - Over-admission is the only failure mode and it is harmless: Ollama queues
     what it cannot serve, which is what happened before. **No fencing token**,
     because Ollama cannot check one; the lease token only stops a holder
     renewing a lease it lost.
5. **Installed at boot** in both processes from `REDIS_URL`; not installed with
   no Redis, a cap of 0, `TALOS_LOCAL_LLM_FLEET_ADMISSION=false`, or a Redis
   unreachable at boot. Every case leaves calls on the process gate.
6. **Series**, closed label set `leased | wait_expired | unavailable |
   lease_lost`, pre-seeded: `talos_local_llm_fleet_admission_total` (controller)
   and `wasm_llm_fleet_admission_total` (worker). No alert: no baseline yet.

**Not done, stated.**

- **Two processes naming one backend by different URLs get different queues**
  and fall back to P3a's bound against each other. Dev and the chart give both
  processes the same `OLLAMA_URL`.
- **A Redis that restarts** loses the queue's state; calls in flight keep their
  process permits and new calls start a fresh queue.
- **Processes with different caps** each apply their own to the shared queue.

### P4 — classification and visibility (proposed)

1. Retry by timeout kind:
   - a first-byte timeout under contention is transient;
   - an idle timeout after progress is a stuck backend, retried once;
   - a ceiling timeout is not retried.
2. Series with closed label sets, pre-seeded:
   - `wasm_llm_timeouts_total{kind}`;
   - per-model queue depth;
   - swap count, derived from the adapter's knowledge of the last-served model.

## Operator items (not code)

- `OLLAMA_CONTEXT_LENGTH=131072` sizes `qwen3.6` at 24.8 GiB. It forces
  `qwen2.5-coder:14b` out on every alternation, and draws Ollama's own warning
  "requested context size too large for model" (`n_ctx_train=32768`) for the
  coder models.
  - A smaller default, or per-request `num_ctx` on the workflows that need 131k,
    would let both models stay resident on this host.
  - That is the operator's decision. P1–P4 do not depend on it.

## Migration and rollout

- **P1** needs no migration and no wire change. Workers roll independently. The
  first-byte and idle deadlines are constants, deliberately not knobs, until P4's
  series give a basis for tuning them.
- **P2a** adds a signed message type on a new subject and no request field, so
  workers and controllers roll in any order: an old controller ignores the
  reports, and a new controller hearing none behaves exactly as before.
- **P3a** needs no migration and no wire change; the controller rolls
  independently. It changes only the controller's own calls.
- **P3b** adds a Redis dependency on the local-inference path, bounded to 2 s per
  call. The fallback keeps a Redis outage from becoming an inference outage. No
  wire change, no migration; processes roll in any order (a process without P3b
  simply is not in the queue).
