# 2026-09-28 — the controller's Ollama calls are gated and on progress deadlines (RFC 0014 P3a)

**Why.** The worker has gated its local LLM calls since #792 and cut them on
progress since P1. The controller's `talos_llm::OllamaClient` had neither: no
gate, one non-streaming request under a 60 s client-wide timeout.

**Measured** (30 days, the host Ollama's request log joined to `llm_usage`;
`scripts/measurements/rfc0014-controller-ollama-overlap.py`):
- 1 072 controller calls: p50 2.2 s, p99 25.4 s, max 46.3 s.
- 106 of them started while another controller call held the backend.
- 108 worker requests arrived while a controller call held the backend (~14 s
  each, 3 failed); 8 of the 33 worker requests cut at exactly 60 s overlapped a
  controller call.
- A failed controller call writes no `llm_usage` row, so controller calls cut at
  60 s cannot be counted from this data.

**Decided.**
- **One leaf crate, `talos-local-inference`,** holds the gate, the streamed
  exchange, its deadlines and the line reader. They moved out of
  `talos-worker-runtime`; the worker keeps thin re-exports (`host::llm_gate`,
  `host::llm_local_stream`, `host::line_reader`, the deadline constants), so its
  call sites and behaviour are unchanged.
- **The gate is generic over `QueueWaitObserver`.** The worker implements it for
  `InferenceWaitLedger` (P2a's reporting stays in the worker); the controller
  passes `None` (`NoWaitObserver`). One semaphore per process, one cap, one env
  var (`TALOS_LOCAL_LLM_MAX_IN_FLIGHT`, now `both` in the configuration
  reference).
- **`OllamaClient::chat`** — the one method every `complete*` call goes through
  — takes its process's gate before its deadlines start, then streams under
  `ProgressDeadlines::LOCAL` and reassembles the non-streaming body, so the parse
  and usage recording are unchanged.
- **A per-request backstop** (`OLLAMA_CHAT_REQUEST_BACKSTOP` = ceiling + 30 s)
  overrides the client-wide 60 s timeout. Without it every streamed answer would
  still be cut at 60 s total.
- **Error wording kept.** An HTTP status reads `Ollama returned HTTP <status>`,
  which `complete_structured` / `complete_with_schema` match for their `think`
  retry. A deadline reads `Ollama made no progress within its <kind> deadline`.
  The provider's own text is never returned; the exchange logs it DLP-redacted.
- **Logging, no metric.** A queued controller call logs at INFO; a wait that
  expired (the call proceeds ungated) logs at WARN. `talos-llm` has no metrics
  edge, and P3b's broker is where the series belong.

**Deliberately NOT done, stated.**
- **Controller and workers do not yet queue against each other.** Each process
  has its own gate, so the 108 controller-vs-worker overlaps are unchanged. That
  is P3b.
- **`warm_model` is not gated.** It runs once at boot under a task timeout that
  would then count the queue wait. `pull` / `show` / `list` / `delete` are not
  inference.
- **The worker's stream tests stay in the worker**: they drive the exchange
  against the worker's provider adapter. The gate's own tests moved to the crate;
  the three ledger tests stay in the worker.
- **The error-body preview** now reads through `talos_http_body::read_body_capped`
  under the same byte cap. Only its overflow log line differs.

**Proof.**
- `talos-llm/src/ollama_chat_tests.rs`, against the production `complete*`
  methods and a loopback Ollama, at millisecond deadlines:
  - the request asks to stream and the answer is reassembled;
  - an answer that keeps progressing outlives a 300 ms client-wide timeout;
  - an answer that stops is cut at the idle deadline;
  - an HTTP 400 still triggers the `think` retry;
  - two calls on one client reach the backend one at a time, with a control
    showing the mock serves two ungated requests at once.
- Reverting each fix fails its test: dropping `stream: true`, dropping the
  per-request backstop, bypassing the gate.
- Gate tests in the crate: the existing cases plus three on the observer (a free
  slot reports nothing; a queued call reports one wait and closes it; no observer
  still queues).
- Suites: 1 041 passed (1 skipped, pre-existing) across `talos-local-inference`, `talos-llm`,
  `talos-worker-runtime` and `worker`. Workspace check (all targets) and clippy
  `-D warnings` on the touched crates are clean.

**Stated limits.**
- No test drives the controller's real callers against a real Ollama. The live
  check after deploy: controller calls that overlap log
  "controller local LLM call queued for the gate", and Ollama's log shows no two
  controller `/api/chat` requests in flight at once.
- The per-process cap means the backend can still see one request per process
  at once: controller replicas + worker replicas.
