# A model call that ran out of budget reasoning: say which call, and let the operator's tool send what a module sends

2026-10-13

## Observed

A module called the local model with options
`{"think": true, "response_format": {"type": "json_object"}}` and
`max_tokens: 1500`. The text that came back held no usable answer.
`test_module` showed `llm_usage: [{"calls": 2, "completion_tokens": 1566, …}]`:
one total for both calls of the run. Working backwards, the second call had
spent all 1,500 tokens reasoning and was cut off. And `local_llm_complete`
took no options, so the same prompt through it answered in 0.6 s and
differently: a prompt tuned through the tool did not behave the same in the
module.

## Found out first

**`stop_reason` was already faithful.** The worker reads Ollama's
`done_reason` and passes it through unchanged
(`llm_providers/ollama.rs`, `stop_reason: r.done_reason`); Anthropic's
`stop_reason`, OpenAI's `finish_reason` and Gemini's `finishReason` likewise.
The host normalises nothing, a decision recorded on 2026-09-30
(`2026-09-30-llm-inference-cut-off-answer.md`) and kept.

Measured on a local model (Ollama 0.35.0, non-streaming `/api/chat`):

| Request | `done_reason` | `eval_count` | content | thinking |
|---|---|---|---|---|
| `think: true`, `num_predict: 40` | `length` | 40 | empty | 120 chars |
| `think: false`, `num_predict: 5` | `length` | 5 | 17 chars | none |
| `think: true`, `num_predict: 600`, a one-number answer | `stop` | 286 | 3 chars | 712 chars |

So a cut during reasoning reports `length` with an empty answer; reasoning
tokens ARE counted in the completion count; and nothing reports them on
their own. The module in question received `stop_reason: "length"` and
`text: ""`. It did not look, and no tool showed it.

## Decided

**Nothing changes in what a module receives.** The defect was that the
answer to "why is this empty" existed and was shown to nobody.

**Each call is kept, in order, beside the totals.** `LlmUsageAcc` was a map
of totals per `(provider, model)`. It is now `LlmUsage`: those totals, plus
the first 20 calls (`MAX_LLM_CALL_RECORDS`) each with its tokens, the
provider's stop reason (bounded, control characters removed) and, where the
call site times it, its duration; the calls past the bound are counted. The
list never leaves the process: the signed result still carries the totals
only, byte for byte. `test_module` renders it as `llm_calls`.

**`local_llm_complete` takes `options`, checked by the worker's code.** The
check that was inline in the host's `complete_with_options` (a JSON object,
at most 8 KiB) is now `talos_worker_runtime::provider_options::parse_provider_options`,
called by the host and by the tool; the translation into a local request is
the worker's own adapter (`apply_to_local_body`). No second validator was
written. The tool returns the answer text as before and, in a second block,
`{model, stop_reason, usage, duration_ms}`, with a note when the answer was
cut off.

**The tool cannot be pointed at another model.** Two layers:
* the worker's translation drops `model`, `messages`, `system`, `stream`,
  `template` and `raw` from options;
* `OllamaClient::complete_with_options` sets `model` back to the model the
  call was made for, restores the messages and sets `stream` itself AFTER
  the options are applied (`local_body_with_options`), and that model is the
  one `refuse_unless_local` is asked about, before the gate, as for every
  other caller. A cloud-hosted Ollama model is still refused.

**Thinking stays off in the tool unless options set it.** A module that sets
no `think` gets the model's own default; the tool's description says how to
reproduce that.

## Deliberately NOT done

* **No normalised stop reason.** A module compares against the provider's
  words; the doc lists them.
* **No reasoning-token count.** No provider path reports one here. For the
  local model the reasoning text is discarded by the stream assembler; its
  token count is inside `eval_count`.
* **The streaming host function records usage without a stop reason**: the
  usage event and the done event are separate there. Its calls are listed
  with `stop_reason: null`.
* **The tools path records no duration** (it does not time the exchange).
* **The classifier templates still do not check `stop_reason`.** The
  2026-09-30 record left them out on purpose; unchanged.
* **`run_sandbox` and the other in-process surfaces do not render
  `llm_calls`.** They pass no accumulator.

## Tests

* `talos-worker-runtime`: a reply cut off while reasoning says `length` with
  no text, and one cut off while answering keeps the text
  (`a_reply_cut_off_while_reasoning_says_length_and_has_no_text`, through
  the stream assembler and the adapter); the call list (order, bound,
  totals unaffected, a provider's stop text bounded); the options rule (the
  size limit at and over the bound, each non-object) and the translation
  (a module's options as the worker sends them; options cannot name the
  model or replace the messages).
* `talos-llm`: options cannot move a completion to another model or prompt;
  `think` is off by default and the caller's when set.
* `talos-mcp-handlers`: `llm_calls` for the observed run (66 then 1,500
  tokens, `stop` then `length`), bounded; the tool's options as a module
  would send them; what the validator refuses (a string, an array, a
  boolean, 9 KiB) in its words; an option naming another model is dropped;
  the report's note.

Mutation (the tool must not reach a model that was not checked): with the
re-assertion of `model` removed from `local_body_with_options`,
`options_cannot_move_a_completion_to_another_model_or_prompt` fails.

## One home

`talos_worker_runtime::provider_options` (what options may be, and what
they become); `talos_worker_runtime::context::{LlmUsage, record_llm_call}`;
`talos_llm::OllamaClient::complete_with_options`.
