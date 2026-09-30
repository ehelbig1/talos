# 2026-09-30 — the LLM Inference template refuses an answer cut off at MAX_TOKENS

**Defect.** A provider that stops because the output budget ran out still
answers 200 with the tokens it produced. The host reports it: Ollama's
`done_reason`, surfaced to the guest as `completion-response.stop-reason`
(`length`; Anthropic `max_tokens`, Gemini `MAX_TOKENS`). The LLM Inference
template never read it, so a cut-off answer was used as if complete.
**Reproduced on the deployed module 2026-09-30** (`test_module`, local
`qwen3.6`, `MAX_TOKENS: 5`, JSON mode): output `{\n  "a` with
`success: true` — a broken JSON object handed downstream as a success.

**Measured** (`llm_usage`, 30 days, output tokens per call against each
workflow's `MAX_TOKENS`): zero calls at the limit, but `pa-inbox-triage`
reached **1 718 of 1 800** (95%). Latent, one long inbox away.

**Fix.** `answer_was_cut_off(stop_reason)` recognises every provider's
spelling (`length`, `max_tokens`, case-insensitive); a cut-off answer fails the
node with the budget, provider and stop reason named and three remedies
(raise `MAX_TOKENS`, ask for less, or opt in). New config
`ALLOW_TRUNCATED_OUTPUT` (default false), documented in `talos.json`, for a
free-text node where a partial answer is acceptable.

**Decisions.**
* **Fail by default, in every mode.** A truncated JSON object is always wrong;
  a truncated free-text answer is usually wrong and silently so. The opt-out is
  per node. Zero measured calls change outcome today.
* **The template recognises provider spellings; the host is NOT changed.**
  `stop-reason` is a published WIT field carrying the provider's raw value;
  normalising it in the host would change what every existing module reads.
* **Not extended to the classifier templates** (Hybrid Classify, Smart
  Classifier): they parse their own small JSON, so a cut-off answer already
  fails their parse.

**Guards.** `every_providers_budget_stop_is_a_cut_off` (template unit test,
run natively from a scratch copy — CI compiles templates via
`make check-catalog` and does not run their tests); `make check-catalog`
green. **The wiring (`run()` refusing) is proven live after deploy**, the
same `test_module` call as the reproduction, which must fail with the new
message; stated rather than implied, since no test drives the template's
`run()`.

**After deploy.** The operator's installed copy (14 nodes) needs the
reinstall already queued for #1001 (`install_module_from_catalog`,
`name: "llm-inference"`) — one reinstall picks up both changes.
