# A local model's system prompt: the drop did not reproduce (2026-10-14)

The local classifier `nimble:9b` was installed with a Modelfile whose
`TEMPLATE` is `{{ .Prompt }}`, beside a baked `SYSTEM`. A template that never
renders `.System` would drop whatever system prompt a caller sends, and the
caller could not tell from the answer. The workflow worked around it by
putting the whole instruction in the user message. The brief said to
reproduce this before changing anything (`ollama show` also reported a Jinja
chat template for the same model), and if it did not reproduce, to record what
was tried and close.

**It did not reproduce. Nothing is changed.**

## What was tried (dev stack, Ollama 0.35.0)

`/api/show nimble:9b`: the Modelfile has `TEMPLATE {{ .Prompt }}` and a
`SYSTEM`, but the `template` field returns a full Jinja chat template (from the
GGUF; family `qwen35`, 9.0B, Q8_0). Which of the two the server applies is a
behavioural question, so it was asked of the server, at temperature 0, against
a control model (`qwen2.5:3b`) whose template has a system slot.

**`/api/chat`, the endpoint every Talos path uses** (`talos-llm`'s
`OllamaClient`, the worker's local provider, the local stream). It sends the
system prompt as a `role: "system"` message, the shape
`host/llm_providers/ollama.rs` builds.

| model | system prompt | prompt tokens | answer to "what colour is the sky, one word" |
|---|---|---|---|
| qwen2.5:3b | "Answer in French." | 32 | Blue |
| qwen2.5:3b | the same + ~300 tokens of padding | 342 | Blue |
| nimble:9b | "Answer in French." | 36 | **Bleu** |
| nimble:9b | the same + ~300 tokens of padding | 346 | **Bleu** |
| nimble:9b | none | 104 | Blue |

The system text reaches `nimble:9b`: its prompt grows by exactly the padding,
as the control's does, and the model follows the instruction (the control
model ignores it). **`/api/generate`** (`system` field, which `ollama run`
and other tools use) gives the same picture: 36 and 266 tokens, "Bleu".

So Ollama renders this model through its Jinja chat template, not through the
Modelfile's `{{ .Prompt }}`.

## What did reproduce, and matters to the workflow

**A caller's system prompt REPLACES the model's baked `SYSTEM`.** With no
system prompt, `nimble:9b`'s prompt is 104 tokens: the baked classification
instructions (schema, one-letter codes), about 57 tokens, are in it. With a
short caller system prompt it is 36: the baked instructions are gone. This is
Ollama's documented behaviour, not a defect.

So the workflow's workaround (the whole instruction in the USER message, no
system prompt) is the shape that keeps the classifier's baked instructions in
force, and it should stay. A workflow that sends this model a system prompt
must restate whatever the baked one said.

## Deliberately NOT done

* Folding a system prompt into the user message for "a model whose template
  has no system slot", or refusing such a model. There is no such model here:
  the guard would act on a Modelfile line the server does not apply, and
  reading `/api/show` per model to decide would be a cache and a request to
  maintain for nothing observed.
* A warning when a caller's system prompt replaces a baked one. It is
  Ollama's behaviour and the author's choice; the paragraph above is where it
  is recorded.

## If it is seen again

A drop would show as the prompt-token count NOT growing with the system
prompt's length (the padding test above, through `local_llm_complete` or the
`llm_calls` record), on that Ollama version, for that model. That is the
evidence to bring.
