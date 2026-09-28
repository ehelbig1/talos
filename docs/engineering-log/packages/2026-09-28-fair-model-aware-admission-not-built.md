# 2026-09-28 — fair, model-aware local-inference admission: measured, not built (RFC 0014 P2c)

**Why this is a record rather than a package.** RFC 0014 proposed two ordering
rules for the worker's local-LLM gate: FIFO across workflow RUNS rather than
across calls, and preferring queued calls for the model already loaded (with an
aging limit). Both were measured before any code was written. On this fleet
neither changes anything worth the complexity, so the operator decided on
2026-09-28 to record the finding and not build.

**Measured.** Source: 30 days of `module_executions` for the 8 modules whose
source calls `llm::complete*` or `complete_with_tools`, 1,445 completed calls.
Each call's model was attributed from its workflow node's `MODEL`.
- **Same-run overlap: 0.** No run ever had two local LLM calls in flight, so
  per-call FIFO already is per-run FIFO.
- **Cross-run overlap: 194 calls (13 %).** Of the overlapping pairs, 139 were
  the same model (`qwen3.6`), 12 were mixed (`qwen2.5-coder:14b` with
  `qwen3.6`), and 33 could not be attributed.
- **Three or more in flight: 87 calls.** Of those, 16 involved a known different
  model, on 5 of the 30 days. This is an upper bound: a module execution's
  interval contains its LLM call and its other work.
- **Only the 3+ case can save a swap.** With two calls in flight the second
  model must load either way. At most one load (3–8 s on this host) is saved per
  event, so about two minutes a month.

**Where swaps come from instead.** Models used one after another over time,
which ordering cannot fix. Keeping both resident does, via
`OLLAMA_CONTEXT_LENGTH` or per-request `num_ctx`: an operator item in RFC 0014.

**Revisit when:**
- a workflow fans out parallel local LLM calls within one run;
- worker replicas grow past one (the gate is per process; see P3);
- mixed-model overlap becomes common.

Re-run the same measurement first:
`scripts/measurements/rfc0014-local-llm-overlap.sql`. It is read-only and holds
all three queries, which reproduce the numbers above.

**Stated limits.**
- Controller-side Ollama calls (`talos_llm::OllamaClient`: consolidation,
  reflection, teacher audit) are not in `module_executions`, so they are absent
  from these counts. They compete at Ollama, not at this gate; that is P3's
  scope.
- The model attribution is by workflow node, so a module whose model comes from
  its own default reads as unattributed.
