# 2026-10-01 — an embedding call's timeout covers its own work, and a failing embedder has series

**What was observed.** One controller WARN at 13:00:22 UTC: "Embedding API
unavailable after retry — falling back to keyword search". First reading: a
cold model load after an idle hour. **Refuted by measurement.**

**Measured (read-only, the embedder's own log, 3.5 days).**
* 2,975 embedding requests; **164 (5.5 %) were cut at the client's 8 s
  timeout**, every one inside a burst. A lone request: p50 0.44 s.
* The model was loaded 17 times in that period — reloads are not the cause.
* The embedder's runner is started `--threads 16 --parallel 1`. Ollama loads
  every embedding model with one request slot ("Embedding models should always
  be loaded with parallel=1", `server/sched.go`), whatever
  `OLLAMA_NUM_PARALLEL` says; and it is CPU-only (Docker on macOS).
* A small synthetic test: one 200-character text 0.3 s, 1,500 characters
  1.6–2.3 s, 6,000 characters 2.7–2.9 s. **Six concurrent 1,500-character
  requests finished at 1.6, 3.2, 5.5, 7.1, 8.6 and 10.1 s** — strictly one
  after another; the last two would have timed out. One batch of the same six
  took 9.1 s: batching buys nothing.
* Bursts come from callers that embed several texts at once (ML serve embeds
  in waves of 8; context assembly and memory writes for parallel nodes).

**The class.** A per-call timeout shared by every request in flight — the
local-LLM gate's class (`talos_local_inference::gate`), one layer over. The
8 s was documented as covering one call's service time; nothing made it so.
And there was no instrument: a lost embedding was one WARN line.

**Fix.**
* `talos_memory::embedding`: a process-wide in-flight gate for a LOCAL
  provider. A call takes a slot BEFORE its timeout starts. Cap
  `TALOS_EMBEDDING_MAX_IN_FLIGHT`, default 1 (measured above); `0` disables;
  an unparseable value is the default, never 0.
* The gate queues and never refuses. A call waits at most twice the
  per-attempt timeout (16 s by default — the time it could already spend on
  two attempts; drains about nine queued calls at the measured rate), then
  goes ahead WITHOUT a slot: the behaviour before the gate. No call that
  would have been made is not made.
* The slot is taken inside the per-key in-flight cell, so callers sharing one
  request share one slot, and a cache hit takes none.
* Every call that reaches the provider reports its gate outcome, queue wait,
  outcome and service time to an observer the controller installs:
  `talos_embedding_requests_total{outcome=ok|rejected|unavailable}`,
  `talos_embedding_gate_total{outcome=acquired|wait_expired|ungated}` (all
  pre-seeded), `talos_embedding_queue_wait_seconds`,
  `talos_embedding_request_duration_seconds`.
* Alert `TalosEmbeddingProviderUnavailable` (warning): more than half of
  calls unavailable over 30 m, with a floor of 5, for 10 m.

**Decisions.**
* Not applied to an external provider (they serve in parallel).
* `talos-memory` does not gain a `talos-metrics` dependency — the worker links
  `talos-memory` and not `talos-metrics`. The controller installs an observer;
  the label spellings are pinned equal by a test in `talos-memory`.
* Raising the timeout was declined: it moves the cliff and does not make the
  timeout a per-call bound.
* Nothing alerts on the gate: `acquired` is the gate working.

**Guards.**
* `embedding::gate_tests` (6): cap parsing; a second call waits and its wait
  is reported; an undrained queue lets the call through; external / disabled
  never queue; a cancelled waiter leaves the gate usable; label sets equal.
* Two integration binaries driving the PRODUCTION `generate_embedding` against
  a one-at-a-time mock backend (300 ms per request, 1 s client timeout, six
  concurrent calls): with the gate all six succeed and the backend never holds
  more than one request; `embedding_gate_disabled_control` runs the same burst
  with the gate off and calls fail — the pre-fix behaviour, reproduced.
* `talos-metrics`: seeding + one call moves its own series.
* promtool: healthy, burst loss past the floor (ratio keeps it quiet), a quiet
  deployment under the floor, `rejected` ignored, provider down fires and
  clears. Both thresholds mutation-checked (`> 0.5` → `> 0`, `>= 5` → `>= 1`:
  each fails a case).

**Stated limits.**
* The gate does not make the embedder faster. A caller with its own, shorter
  deadline still gives up first: the worker waits 3 s for a memory call and
  10 s for an ML batch, while a wave of 8 uncached 1,500-character texts costs
  about 13 s on this embedder. Those results now complete and are cached
  (5 minutes) instead of being cut at 8 s.
* Per process: `replicas × cap` against one backend.
* `talos-search-service`'s embedding client (operator-invoked workflow search)
  is a second client and is not gated.
* Worst case for one call grows from 16 s (two attempts) to 32 s (a full wait,
  then two ungated attempts) — only when the queue did not drain in 16 s.
* The controller's observer wiring is in the binary and not driven by a test;
  the guard is the series moving after deploy.

**Not done — an operator's choice.** Throughput is set by the embedder: a
CPU-only container at one request at a time. Pointing `EMBEDDING_API_URL` at a
GPU-backed local embedder would be an order of magnitude faster; it changes
which machine computes vectors and possibly their low bits (ML content
identity hashes embeddings), so it is not changed here.
