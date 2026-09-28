# 2026-09-28 — a local LLM call is cut when it stops making progress (RFC 0014 P1)

**Why.** `pa-chief-of-staff` failed on 2026-09-28: `synthesize` (`qwen3.6`,
`MAX_TOKENS` 1800) was cut at 60 s on all three attempts. The operator asked for
concurrent workflows to stop needing careful scheduling. RFC 0014 sets out the
whole fix in four phases; this is phase 1.

**Measured (host Ollama request log, 2026-08-27 → 09-28).**
- 33,891 `/api/chat` requests. Of the 33,808 that succeeded, p99 was 19.9 s.
- **47 requests were cut at 59.7–60.0 s.** Ollama logs a 500 when the client
  hangs up, so these are our deadline firing, not an Ollama error.
- **19 of September's 20 weekday mornings** had a 60 s cut between 07:55 and
  08:15, when six workflows start together.
- **09-28:** `synthesize`'s first attempt was the only request in flight from
  07:37 until it was cut at 08:01:14, with no model load in between. A healthy
  generation on an idle, loaded model was killed by the clock.
  - Attempts 2 and 3 each paid a model swap (`qwen2.5-coder:14b` in between) and
    were cut too.
- Most mornings a caller absorbs the error: the workflow completes with no
  `node_retrying` event. Which caller it is cannot be attributed, because the
  worker log does not survive a restart.
- **Not measurable:** the true service time of the 47 cut calls. Every one was
  aborted at 60 s. This package does not depend on that number.

**Decided.**
- **Local exchanges stream.** Both call sites, `llm::complete*` and
  `llm-tools::complete-with-tools`, send `stream: true`.
  - The host sets this after the adapter and guest options have shaped the body.
    The adapter still re-asserts `stream: false`, so a guest cannot change it.
  - `llm_local_stream::OllamaStreamAssembler` rebuilds the non-streaming
    response: concatenated content, every `tool_calls` entry, and the counts and
    `done_reason` from the `done` line.
  - The rebuilt response goes to the adapter's **unchanged** parser.
  - `thinking` counts as progress and is dropped from the content, as the
    non-streaming API does.
- **Three deadlines replace the one:** first byte 60 s, idle 60 s, ceiling
  600 s (`limits.rs`).
  - **Pareto:** a call that finished inside the old 60 s total also meets the new
    rule, so no call that works today can fail. This is pinned at compile time
    (`const _: () = assert!`).
  - An idle deadline under 60 s was rejected on that property: Ollama sends
    nothing while it buffers a tool call's text.
  - Headers do not start the idle clock: a 200 followed by silence is a
    first-byte timeout.
- **Classification is unchanged.** Deadline → `Timeout`, with the kind in the
  WARN line (not a label until P4). Mid-stream `{"error"}` → `HttpStatus`, as the
  same failure was when it arrived as an HTTP 500. Ended before `done` →
  `Network`. Over the wire cap → `OversizedResponse`. Bad line → `Decode`.
- **Unchanged:** external providers (non-streaming, 120 s total), the guest's
  own `llm_streaming`, and the controller's `OllamaClient` (RFC 0014 P3).
- **Also changed.**
  - The `llm-inference` template's timeout message named a "default 30s" that
    never existed and advised a smaller `MAX_TOKENS`, which no longer helps a
    local call. It now describes the progress deadlines. Two installed modules
    keep the old text until they are reinstalled.
  - The `metrics.rs` bucket doc no longer claims a local call cannot exceed 60 s;
    the `60000` boundary is kept.
  - **The pre-commit hook refused this commit.** `scripts/lib/workspace-crates.sh`
    mapped a staged `module-templates/llm-inference/template.rs` to its own
    `[package]` (`llm-inference`), which is not a workspace member, so
    `cargo check -p llm-inference` failed. Every commit touching a catalog
    template was blocked. `crate_for` now requires the directory to be listed
    in the root `members`. Checked against `cargo metadata`: all 148 members
    still map, and a template path maps to nothing.

**Proof.**
- `llm_local_stream_tests` (18 tests):
  - Assembly equals the non-streaming parse at every byte split, including
    inside a multi-byte character, for both content and tool calls.
  - Error line, no `done`, non-JSON, wire cap.
  - A loopback server at millisecond scale: a steady answer three times longer
    than any single deadline completes; idle, first-byte, headers-only and
    ceiling cases; 500 and 429 keep their classes; an early close is `Network`.
- `llm_failure_metrics_tests`, through the guest entry points:
  - both call sites send `stream: true`;
  - an answer paced at one chunk per 20 s of virtual time, 100 s in total,
    completes;
  - a streamed tool call reaches the guest with its arguments and usage;
  - every existing failure-class case passes against the now-streaming mock.
- **Fails on the pre-fix behaviour.** With both call sites back to
  non-streaming under a 60 s total, the 100 s test fails with `Error::Timeout`,
  the 09-28 symptom, and the streaming-request test fails. Restored and
  re-checked.
- `talos-worker-runtime` + `worker`: 991 passed (nextest). The in-process
  `cargo test --lib host::llm` passes too, 97 tests. Clippy
  `--all-targets -D warnings` and rustfmt are clean.
- Not mutation-tested: no security gate is involved.

**Stated limits.**
- **No test drives a real Ollama.** The live check after deploy: tomorrow's 08:01
  window in `~/.ollama/logs/server.log` shows no 500 at ~60 s, and
  `pa-chief-of-staff` completes.
- P1 does not stop queue time being charged to a node's 120 s attempt window or
  the workflow budget (P2). It does not coordinate replicas or the controller
  (P3), and it does not change retry behaviour (P4). A generation that needs more
  than its attempt window still fails, now through the engine's clamp rather than
  this deadline.
- **Operator item, unchanged:** `OLLAMA_CONTEXT_LENGTH=131072` makes the two
  models evict each other on every alternation (RFC 0014, operator items).
