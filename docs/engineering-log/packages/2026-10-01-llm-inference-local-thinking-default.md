# 2026-10-01 — the LLM Inference template turns thinking off for a local call unless the node asks for it

**Defect.** The template passed no `think` field to Ollama unless the node
put one in `PROVIDER_OPTIONS`, so a thinking model ran with its own default.
`qwen3.6` thinks by default and spends its output budget on reasoning before
it answers. **Reproduced on the deployed module 2026-10-01** (`test_module`,
local `qwen3.6`, `MAX_TOKENS: 200`, asked for one word, no `think` option):
all 200 tokens went to reasoning. Before the cut-off check
([`2026-09-30-llm-inference-cut-off-answer.md`](2026-09-30-llm-inference-cut-off-answer.md))
that was an empty answer reported as success; since it, the node fails with
"cut off at MAX_TOKENS=200". Either way a new node has to know to write
`think: false` by hand.

**Reach, measured.** 14 live nodes use the installed copy: 11 on `qwen3.6`,
all 11 with `think: false` already set; 3 on `qwen2.5-coder:14b`, which has no
thinking mode. So no production node changes behaviour — the default writes
down what every node had to say for itself. The controller's own local calls
got the same default in
[`2026-09-30-controller-llm-thinking-off.md`](2026-09-30-controller-llm-thinking-off.md).

**Fix.** `apply_local_thinking_default` inserts `think: false` into the
provider options when the provider is Ollama and the node set neither `think`
nor `reasoning_effort`. `talos.json` documents the default and how to turn
thinking on.

**Decisions.**
* **The node's choice always wins.** `think: true`, a level (`"low"`), `false`,
  `null` (the model's own default) and either `reasoning_effort` spelling are
  left exactly as written.
* **In the template, not the host.** The worker's Ollama adapter sends `think`
  only when the caller asked; changing that would change every module that
  calls `llm::complete`, including custom ones whose authors chose a thinking
  model for its reasoning.
* **No retry without the field.** Ollama accepts `think: false` for a model
  with no thinking mode (measured on 0.31.2 and 0.35.0; only `think: true` is
  rejected there), and a server that predates the field ignores it. The
  controller keeps its one-shot 400 retry; the template cannot see a status
  code, and a second attempt here would be a second LLM call.
* **Other providers are untouched**, so a node with no options still takes the
  plain `complete` path.

**Behaviour change, stated.** On another deployment, a node on a thinking
local model with no `think` option now answers without reasoning. Set
`PROVIDER_OPTIONS: {"think": true}` to keep it.

**Guards.** `a_local_call_defaults_thinking_off_and_the_nodes_choice_wins`
(template unit test: nothing said, unrelated options, six explicit choices,
a non-local provider), run natively from a scratch copy — CI compiles
templates with `make check-catalog` (green) and does not run their tests.
The wiring in `run()` is proven live after deploy: the reproduction above
must return the one word.

**After deploy.** The operator's installed copy needs one more
`install_module_from_catalog` (`name: "llm-inference"`) to pick this up.
