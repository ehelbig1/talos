# 2026-09-30 — an answer to a prompt Ollama truncated is refused

**Defect (latent).** When a prompt is longer than the context the model is
loaded with, Ollama does not refuse it: it drops the start, evaluates the rest,
answers HTTP 200 and says nothing in the response. Measured on the reference
host (Ollama 0.35.0, `qwen2.5:3b`, a 22 925-token prompt whose system prompt
said "reply BANANA"): with `num_ctx: 4096` Ollama evaluated **2 050** tokens and
answered about "a list of numbers" — the system prompt was gone; with
`num_ctx: 32768` it evaluated all 22 925 and answered "BANANA". The only trace
is a server-log WARN, `truncating input prompt limit=2050 prompt=22925`.

**Why latent.** The host runs `OLLAMA_CONTEXT_LENGTH=131072` (server log), and
the largest local prompt in 30 days was ~62k tokens (`pa-chief-of-staff`).
Across all six retained Ollama server logs the only truncation WARN is the
experiment above. No node sets `num_ctx`, so every call depends on that host
setting (Ollama's own default is 4k/32k/256k by VRAM), and nothing in Talos
would notice if it changed.

**The signature (measured).** A truncated prompt reports
`prompt_eval_count = context/2 + 2` — 4 096 → 2 050, 8 192 → 4 098,
6 000 → 3 002 — and `/api/ps` reports each loaded model's `context_length`.
So truncation is DETECTED, not estimated from character counts.

**Fix.** `talos_local_inference::context`: `truncation_signature(count, ctx)`
(`count ∈ [ctx/2, ctx/2 + 8]`), `check_prompt_fit(client, base_url, model,
prompt_eval_count) -> PromptFit {Fits, Truncated, Unknown}` with `/api/ps`
cached 30 s per base URL (re-read once when the model is missing), and
`truncation_message` (counts and the remedy, never prompt text). Applied after
the response on all three local paths: the worker's `complete*`
(`LlmFailure::PromptTruncated`, guest `invalid-request`), the worker's
`complete-with-tools` (guest `invalid-request`), and the controller's
`OllamaClient::chat` (`Err`, never containing `HTTP 400`).

**Decisions.**
* **A detector, not an authorization gate — Unknown keeps the answer.** It
  runs after the answer exists; an unreadable `/api/ps`, a model no longer
  loaded, or a missing count yields `Unknown` and the answer stands. Refusing
  there would turn a monitoring hiccup into failed runs for answers that are
  almost always sound.
* **A detected truncation fails the call** — the answer was written without
  the system prompt. The tokens were spent and are still recorded.
* **Prompts under 1 024 evaluated tokens are not checked** (no request): a
  truncation there needs a context under 2 048.
* **New label `prompt_truncated`, seeded for `ollama` only** — only a local
  exchange is checked, so the three external pairs are unreachable and are
  NOT seeded (the seeding tripwire moved 31 → 32 and its sibling predicate
  now names the carve-out).
* **Streaming is NOT covered** (`start-stream` / `start-tool-stream` deliver
  usage in the final event to the guest) — stated.

**Stated limits.** A genuine prompt of exactly `ctx/2 … ctx/2 + 8` tokens
(65 536–65 544 at this host's context) would be misread as truncated. The
`+ 2` is Ollama 0.35.0's; the 8-token window absorbs a small change, a larger
one would blind the detector (it would return `Fits`, i.e. today's behaviour).
A model reloaded with a different context between the call and the `/api/ps`
read could be judged against the wrong context.

**Guards.** `context` unit tests (the three measured points and their
neighbours); `tests/context_fit.rs` against a loopback `/api/ps` (signature,
one read for repeated checks, small prompts make no request, Unknown for an
unreadable `/api/ps` / an unloaded model / no count and not cached, re-read on
a cached miss); `talos-llm` `an_answer_to_a_truncated_prompt_is_refused` with
a non-signature control; worker
`an_answer_to_a_truncated_prompt_is_refused_and_counted` (metric moves exactly
once) and `a_tool_call_answer_to_a_truncated_prompt_is_refused`. Each refusal
test fails on `main`.
