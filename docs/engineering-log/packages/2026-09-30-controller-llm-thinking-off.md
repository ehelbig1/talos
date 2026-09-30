# 2026-09-30 — the controller's plain local completion turns thinking off

**Defect.** `talos_llm::OllamaClient::complete` was the one controller call to
the local Ollama that sent no `think` field, so it ran with the model's
default. Ollama's docs (checked 2026-09-30) define `think` as `true` / `false`
/ a named level / `null` = model default, and `/api/show` on this host reports
`qwen3.6:latest` `thinking = {values: [false, true], default: true}`. A
thinking model therefore spent its `num_predict` budget reasoning before the
answer — the failure the teacher audit had measured on 23 of 100 replies
(2026-07-21), which is why `complete_structured` / `complete_with_schema`
already sent `think:false`.

**Reach, measured.** Plain `complete()` has two callers: graph-RAG extraction
(`TALOS_GRAPH_RAG_MODEL=qwen2.5-coder:7b` here, which has no thinking mode —
so LATENT today, and live the day that model is changed) and
`local_llm_complete`. Every workflow LLM node already sends `think:false`
(16 of 16, directly or via the Hybrid Classify / Smart Classifier templates).

**Fix.** `OllamaClient::chat_thinking_off` is the one home for "send
`think:false`; on an HTTP 400 retry once without `think`". All three
completion methods use it; the two hand-copied retry blocks are gone.

**Decisions.**
* **The 400 retry is kept, and its cost measured**: on Ollama 0.35.0
  `think:false` is ACCEPTED by models without a thinking mode (HTTP 200 for
  `qwen2.5-coder:7b` and `qwen2.5:3b`); only `think:true` is rejected
  (`"… does not support thinking"`). So on this server the retry never fires;
  it stays for servers that reject the field.
* **Only a 400 retries** — a 401/404/429/500 fails at once (pinned).

**Guards.** `plain_complete_turns_thinking_off_and_retries_without_it_on_400`
(first request `think:false`, retry has no `think`, same messages, no
`format`); `a_non_400_failure_is_not_retried_without_think` (one request); the
existing reassembly test now asserts `think:false`. Both new tests fail on
`main`.
