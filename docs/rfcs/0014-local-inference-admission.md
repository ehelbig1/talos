# RFC 0014 — Local inference that does not depend on the schedule

**Status:** In progress — P1 (progress-based deadlines) 2026-09-28
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
   deadlines, and waiting calls are admitted fairly and model-aware.
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

### P2 — waiting is not charged; admission is fair (proposed)

1. **The worker reports queueing.** While a call waits for a local slot, the
   worker publishes a signed, rate-limited "waiting for local inference" progress
   message on the job's reply channel.
   - The dispatcher extends that attempt's deadline by the reported wait, bounded
     by the workflow budget, which stays the one hard wall-clock limit.
   - The worker's own job timeout excludes gate wait in the same way.
   - Open question: a new signed message type needs `verify()` and
     `verify_no_replay()` from day one (CLAUDE.md, verify-once rule), and the
     platform-primitive checklist.
2. **Fair order.** FIFO across *workflow runs*, not across calls, so one run's
   fan-out cannot starve the others.
3. **Model-aware order.** Among waiting calls, prefer those for the model already
   loaded, with bounded unfairness (an aging limit). This measurably saves 3–8 s
   per avoided swap and removes the retry-amplified thrash seen on 09-28.

### P3 — fleet-wide admission (proposed)

1. A Redis-backed lease semaphore (TTL-renewed, fenced by a token), keyed per
   backend, taken by every worker replica **and** the controller's `OllamaClient`.
2. **The broker never refuses**, like the gate: if Redis is unreachable, a caller
   falls back to its per-process gate and logs it.
3. The controller's `OllamaClient` moves to the same streaming progress deadlines
   as P1.

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
- **P2** adds a signed message type. Deploy ordering will be stated with it
  (workers first, as with every signed-field addition).
- **P3** adds a Redis dependency on the local-inference path. The fallback keeps
  a Redis outage from becoming an inference outage.
