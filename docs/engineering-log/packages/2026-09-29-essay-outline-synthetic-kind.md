# 2026-09-29 — the essay generator grounded on its own last outline

**Found live.** `content-pipeline-weekly` asks a local model to invent a
fresh, non-obvious essay topic each week and persists the outline to its
actor's memory (`essay_outline/weekly-suggestion`). The write carried no
`metadata.kind`, so the smart actor-context builder handed each run the
previous week's outline as grounding. `execution_memory_context` records it
at rank 0 or 1 on every run.

**The effect, measured over the last four runs.** The topic settled into a
two-week cycle:

| Run | Title |
|---|---|
| 09-07 | WASM Capability Sandboxing: Security and Performance Paradox |
| 09-14 | Credential-Free Workers in Self-Hosted Workflows… |
| 09-21 | the 09-07 title and thesis, word for word |
| 09-28 | Credential-Free Workers: Rethinking Authentication… |

Each run's output was a function of its own previous output. That is the
hallucination-amplification case the `metadata.kind` convention in CLAUDE.md
exists for.

**Decided.**
- The node now stamps `MEMORY_WRITE_METADATA_KIND = essay_outline`, a live
  config change the operator approved (graph version 2). The installed LLM
  Inference module already reads that key. The upsert overwrites `metadata`,
  so the one existing unlabelled row is relabelled on the next write.
- `essay_outline` joins `talos_memory::SYNTHETIC_MEMORY_KINDS`. The label
  alone changes nothing: the grounding filter and the graph auto-extraction
  skip both read that list. With both halves, the outline is excluded from
  grounding and is no longer mined into the entity graph. It stays readable
  through `actor_recall*`.
- `docs/smart-actor-context.md`'s copy of the list was already stale (missing
  `reflection` and `consolidated`) and now matches the code.

**Proof.** `essay_outline_is_synthetic` fails with the list entry removed
and passes with it. `talos-memory` (207) and `talos-actor-memory-service` (8)
lib suites pass.

**Stated limits.**
- **This breaks the loop; it does not make topics fresh.** Without last
  week's outline the model sees only the persona and the entity graph, and it
  may settle on one topic. Real freshness needs the prompt to see prior
  titles framed as "already covered", which is a workflow design change and
  was left for the operator.
- **Entities already mined from past outlines stay in the graph.** The
  change stops new extraction only.
- **Verified by the next scheduled run** (2026-10-05 12:00 UTC):
  `execution_memory_context` for that execution should not list
  `essay_outline/weekly-suggestion`, and the row should carry
  `metadata.kind = essay_outline`.
- Also seen, not changed: the model (`qwen2.5-coder:14b`) emits invalid JSON
  (unquoted bullet strings) in two of the four outlines.
