# 2026-09-28 — local LLM timeouts classified and counted by kind (RFC 0014 P4a)

**Why.** Since P1 a local LLM exchange is cut by one of three deadlines — first
byte, idle, ceiling — and they mean different things. The retry decision could
not tell them apart: the guest sees one `timeout`, and every classifier read it
as transient.

**Measured first.** The host Ollama's request log, 2026-09-21 to 2026-09-28:
- every local LLM failure was either the old 60 s total cut (11) or an HTTP 500
  (2);
- P1 removed that cut, and since P1–P3 deployed there have been none.

So retry-by-kind had no population when built. It was built on the operator's
decision (2026-09-28, "all of Phase 4"); the counter below will show whether it
ever acts.

**Decided.**
- **Three `reason_class` tokens**:
  - `inference-first-byte-timeout` — transient, the node's own retry count;
  - `inference-idle-timeout` — transient, capped at ONE retry;
  - `inference-ceiling-timeout` — not retried (in `NON_TRANSIENT`).

  They are named `inference-*` rather than `llm-*` so they carry no `llm`
  needle, and are exempt by name from the foreign-needle test like `timeout`,
  since they are timeouts.
- **Latched at both local call sites** (`complete`, `complete_with_tools`)
  through `TalosContext::record_inference_timeout`, on the existing egress
  latch:
  - a later HTTP failure overwrites it (the four HTTP surfaces latch or clear
    on every failing return), so an LLM class cannot ride one;
  - only a timeout latches; other local failures do not clear the latch, since
    that could remove an earlier non-transient HTTP marker.
- **The pairing is two spellings**: the variant's `Timeout` and the
  `llm-inference` template's "timed out". `Reason::explains` reads an
  `|`-separated set; every existing pairing is a single spelling, so they are
  unchanged.
- **The cap has one home**: `talos_retry_intelligence::retry_cap_for`.
  - `RetryClassifier::retry_cap` defaults to `None` and can only lower the
    count: the dispatcher takes the smaller of the cap and `max_retries`.
  - A cap that stops retries early writes a `retry_skipped` event with
    `error_class`.
- **Mirrors kept in step**: `talos-reason-class` (tokens; `Family::Timeout` for
  all three), the failure-analysis table and the ops self-monitor table. To an
  operator all three still read as a timeout.
- **Series**, closed set `first_byte | idle | ceiling`, all pre-seeded, counted
  at the exchange's one deadline site (`talos_local_inference::stream::
  set_timeout_sink`):
  - worker: `wasm_llm_timeouts_total{kind}`;
  - controller: `talos_local_llm_timeouts_total{kind}`, duplicated into
    `talos_metrics::LocalLlmTimeoutKind` and pinned equal by a controller test.
  - Both are installed at boot, independent of Redis. No alert: no baseline.

**Deliberately NOT done, stated.**
- A `retry_condition` bypasses the classifier, and so the cap, as it does for
  every class.
- A module that rewrites the LLM error without "timeout" or "timed out" loses
  the marker, and reads as before.
- The controller's `OllamaClient` callers are counted, not retried by kind.
- Pipeline steps (dormant by config) read the worker's own transient check,
  which treats only the ceiling differently.

**Proof.**
- **Production path** (`llm_failure_metrics_tests`), each asserting the marker
  on both the `Debug` rendering and the template's prose:
  - a stall before the first byte is marked `inference-first-byte-timeout`;
  - a stall after one chunk (a new `mock-idle`) is marked
    `inference-idle-timeout`, through `complete`;
  - the same through `complete_with_tools`.
- **Classifiers:**
  - every token lands in its class with the right transience (retry
    intelligence's table);
  - only the idle class is capped, and an unmarked LLM timeout still reads
    `timeout`, transient;
  - the production `HeuristicRetryClassifier` carries the cap and the ceiling
    reading end to end;
  - the worker's own check reads only the ceiling as non-transient.
- **Dispatcher:**
  - a class capped at 1 stops after one retry although the node allows three;
    the control uses all three;
  - a cap never raises a node's count.
- **Sink** (`talos-local-inference/tests/timeout_sink.rs`): each kind is counted
  once; a complete answer counts nothing.
- **Series:** both counters are pre-seeded and move by kind; the controller's
  labels are pinned to the stall kinds.

**Mutations: 9 applied, 9 caught.**

| Mutation | Caught by |
|---|---|
| ceiling arm removed | the classifier table, the production-classifier test |
| idle cap removed | the cap test, the production-classifier test |
| the production classifier does not return the cap | the production-classifier test |
| the dispatcher ignores the cap | the dispatcher cap test |
| `complete` does not latch | the first-byte and idle tests |
| `complete_with_tools` does not latch | the tool-call idle test |
| single-spelling pairing | all three production-path tests |
| the sink is never called | the sink test |
| ceiling not in `NON_TRANSIENT` | the snapshot, and the behavioural test |

The last one was first caught only by the literal snapshot; the behavioural
test was added so it is caught by behaviour too.

**Suites:** 1 524 passed (1 pre-existing skip) across the touched crates, plus
the controller's label pins. The workspace check (all targets) and clippy
`-D warnings` are clean.

**Stated limits.**
- No test drives a real Ollama stall end to end through the dispatcher. The
  live check after deploy: both `…_timeouts_total` series export zeros.
- When a timeout happens, its node failure carries the marker. A ceiling
  timeout, or an idle one past its one retry, also writes a `retry_skipped`
  event whose `error_class` names the class.
