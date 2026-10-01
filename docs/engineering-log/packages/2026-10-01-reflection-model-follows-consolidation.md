# 2026-10-01 — the reflection model follows the consolidation model when unset

**Defect.** `MEMORY_REFLECTION_MODEL` and `MEMORY_CONSOLIDATION_MODEL` each
defaulted to the literal `qwen2.5:7b`, independently, while the reflection
accessor's own doc said its default "matches consolidation's". On the
reference host the operator set `MEMORY_CONSOLIDATION_MODEL=qwen3.6` and left
reflection unset, so the controller ran with consolidation on `qwen3.6` and
reflection on `qwen2.5:7b` — a model the local Ollama does not have (ten
models pulled, that one not among them).

**Why it matters.** Reflection is local-first for every tier. For a tier-2
actor a failed local attempt falls back to the EXTERNAL provider
(`run_reflection_tick`, by design, budget-gated). A local model that does not
exist always fails, so an unset default decided that a tier-2 actor's
memories would be sent to the external provider. A tier-1 actor never
egresses; there the same default just means no reflection.

**Latent on this fleet, measured.** No actor reaches the reflection LLM today:
the tier-1 actors are skipped (`MEMORY_REFLECTION_TIER1_LOCAL_OK` unset) and
the one tier-2 actor with memories has 5 of the 8 required. 30 days of
`llm_usage` hold no external-provider row. The last reflection written is
from 2026-07-23.

**Fix.** `talos_config::memory_reflection_model()` returns
`memory_consolidation_model()` when `MEMORY_REFLECTION_MODEL` is unset or
blank. One knob sets both loops; the reflection variable exists to make them
differ. With both unset the answer is unchanged (`qwen2.5:7b`).

**Not changed.**
* The literal `qwen2.5:7b` default for consolidation and for
  `TALOS_GRAPH_RAG_MODEL`. A default has to name some model and cannot know
  what a host has pulled; the bundled compose file sets the graph model
  itself.
* The tier-2 external fallback. It is the documented design.
* No boot check that a configured local model is present. A missing model
  already fails loudly per tick ("local LLM reflection failed").

**Behaviour change, stated.** A deployment that set
`MEMORY_CONSOLIDATION_MODEL` and relied on reflection staying on `qwen2.5:7b`
now reflects with the consolidation model. Set `MEMORY_REFLECTION_MODEL` to
keep them apart.

**Guard.** `test_memory_reflection_config`: unset and blank follow the
configured consolidation model; an explicit value wins and does not move
consolidation. Fails on the unfixed accessor.

**After deploy, here.** Reflection resolves to `qwen3.6`. Nothing observable
changes until an actor passes the reflection gates.
