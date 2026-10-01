# 2026-10-01 — module rehearsal tools: earlier-node outputs, usage and fuel, lint with dependencies

Four gaps found while building a workflow whose modules read an earlier
node's output and call a local model.

**1. `test_module` could not supply `__accumulated__`.** In a workflow the
engine gives every node the outputs of the nodes before it under
`__accumulated__` — the only way to reach a non-parent node's output.
`test_module` built its payload from `config` and `input` only. (A caller could
get a root `__accumulated__` by nesting one inside `input`, because input keys
are merged at the root — an accident, not a contract.) Now: an `accumulated`
argument (object, ≤ 1 MB), delivered as `data["__accumulated__"]`. The payload
builder is the pure `test_module_payload`; only the argument sets the root
key, and a same-named key inside `config` / `input` is no longer promoted.

**2. `test_module` reported neither fuel nor LLM usage.** A failed run has no
output to carry `__fuel_consumed__`, and nothing said how many tokens an
LLM-backed module used against its `MAX_TOKENS`. The runtime already had both
accumulators (`llm_usage_out`, `fuel_out`); the handler passed `None`. Now the
reply carries `fuel: {consumed, limit}` and
`llm_usage: [{provider, model, prompt_tokens, completion_tokens, calls}]` on
the success AND the failure arm. Each is `null` when nothing was measured,
which is not zero.

**3. `lint_sandbox` took no `dependencies`.** Its description told authors a
module importing `chrono` could not be linted. `CompilationService::lint_code`
already accepted them; the handler passed `None`. Now the argument is
validated by the same allowlist as `compile_custom_sandbox` and forwarded.

**4. `compile_custom_sandbox` did not say what fuel limit it computed.** The
success text now states `max_fuel`.

**Decisions.**
* **`accumulated` is caller-authored data to the caller's own module.** The
  engine strips engine-authored keys from inbound TRIGGER payloads because
  there a caller could spoof context to someone else's workflow; a rehearsal
  has no such boundary — the caller already supplies the whole payload.
* **No stop reason in the reply.** The usage accumulator carries token counts
  only; a cut-off is already an error from the LLM Inference module.

**Not changed.** `run_sandbox` still reports neither usage nor fuel.

**Guards.** Five unit tests on the pure helpers (`rehearsal_tool_tests`): the
payload shape with and without `accumulated`, a nested same-named key not
promoted, the unchanged legacy shapes, usage `null` vs sorted rows, fuel
`null` vs measured.

**Stated limits.** The handler wiring (the two accumulators passed to the
runtime, `dependencies` passed to `lint_code`) is not driven by a test — it
needs a compiled module and the compile sandbox. Verify after deploy:
`test_module` on an LLM module returns `llm_usage`; `lint_sandbox` with
`{"chrono": "0.4"}` lints a module that imports chrono.
