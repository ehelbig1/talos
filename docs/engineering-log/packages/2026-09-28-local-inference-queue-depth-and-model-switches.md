# 2026-09-28 — local-inference queue depth and model switches (RFC 0014 P4b)

**Why.** The last phase of RFC 0014. After P3b one Redis queue admits every
local LLM call on the fleet. Two questions it could not answer:
- How deep does the queue get when calls arrive?
- How often does an admission switch the backend to a different model? That is
  the swap that makes a call pay a model load (P2c).

**Decided.**
- **Depth is recorded per ARRIVAL.** The queue's first answer to a call is its
  position: how many calls must be admitted before it, 0 when admitted at once.
  It is recorded once per call as a histogram:
  - worker `wasm_llm_fleet_queue_ahead`;
  - controller `talos_local_llm_fleet_queue_ahead`;
  - one bucket set, `fleet::QUEUE_AHEAD_BUCKETS` = `0, 1, 2, 3, 4, 6, 8, 12,
    16`, pinned equal to `talos_metrics::LOCAL_LLM_QUEUE_AHEAD_BUCKETS` by a
    controller test;
  - not seeded (the house rule for histograms).
- **A sampled gauge was REJECTED.** A herd lasts tens of seconds, so a 15 s
  sample reads 0 almost always and can miss one entirely.
- **Per-model depth deliberately NOT built.** Model names come from workflow
  configuration; a model label would be caller-influenced cardinality.
- **Model switches are decided in the admission script.**
  - A fifth key per backend holds the last admitted model (24 h TTL).
  - An admission for a different model returns `-2` instead of `-1`, so the
    comparison is atomic with the admission and ordered across processes.
  - An empty model is not compared; a name is cut to 128 bytes on a char
    boundary.
  - Series: worker `wasm_llm_fleet_model_switches_total`, controller
    `talos_local_llm_fleet_model_switches_total`. Seeded at 0, no model label.
    Each process counts its own admissions; sum both for the fleet.
- **The model reaches the queue from all three call sites**: worker `complete`
  and `complete_with_tools`, and the controller's `OllamaClient::chat`, through
  `gate::acquire_process_slot(wait, model)`.
- **`FleetSink` takes a `FleetEvent`** — `Outcome` (P3b), `Arrival { ahead }`,
  `ModelSwitch` — so one hook carries everything the queue reports.
- **The controller records into an EXPLICIT registry** (`record_fleet_event(m,
  …)`, the `*_on` functions). The global-registry wrappers
  `record_local_llm_fleet_admission` / `record_local_llm_timeout` (P3b / P4a)
  lost their only callers and were deleted.

**Deliberately NOT done, stated.**
- Calls that never reach the fleet queue — no Redis, the queue switched off, or
  Redis failing — record no arrival and no switch.
- A switch is a proxy for a swap: whether Ollama evicted a model depends on
  memory Talos cannot see. P2c's measurement from Ollama's own log is the
  ground truth.
- No alert: no baseline.

**Proof.**
- **Against a real Redis** (`tests/fleet_redis.rs`):
  - switches counted across two processes: the first admission, same-model
    admissions and an unknown model count nothing; a change counts once, by the
    process that made it;
  - arrivals: a holder reads 0, the next caller 1, the one after 2.
- **Sinks:**
  - the controller's `record_fleet_event` moves exactly the named series;
  - the worker's sink does the same against the real exporter.
- **Call sites:** a textual pin per site that the model is passed. The queue is
  not installed in those test binaries, so no behavioural test can see the
  argument there.
- **Series render** (`talos-metrics`): the switch counter exports 0 cold; the
  histogram buckets its observation.

**Mutations: 11 applied, 11 caught — one after it first SURVIVED.**

| Mutation | Caught by |
|---|---|
| switch never reported | the switch test |
| same model counted as a switch | the switch test |
| arrival not recorded | the arrival test |
| arrival recorded every poll | the arrival test |
| the gate drops the model | the switch test |
| a worker call site drops the model | the worker pin |
| the controller drops the model | the controller pin |
| the controller sink ignores switches | the controller sink test |
| the controller sink ignores arrivals | the controller sink test |
| the worker sink ignores switches | the worker sink test |
| the worker sink ignores arrivals | the worker sink test |

The controller-sink mutation first **survived**: the sink wrote to the
process-global registry, which no test could observe. It was closed by
routing the sink through an explicit registry, which is also why the
global-registry wrappers could be deleted.

**Suites:** 1 106 passed (1 pre-existing skip) across the touched crates with
Redis, plus the controller's four sink and label tests. The workspace check (all
targets) and clippy `-D warnings` are clean. The Redis tests ran against a
throwaway container, not the stack's Redis.

**Stated limits.**
- No test drives the controller and a worker together against the stack's Redis
  and a real Ollama. The live check after deploy:
  - `_queue_ahead_count` climbs with every local call on both processes;
  - the 08:00 herd shows observations above bucket 0;
  - `_model_switches_total` moves when the fleet alternates models.
