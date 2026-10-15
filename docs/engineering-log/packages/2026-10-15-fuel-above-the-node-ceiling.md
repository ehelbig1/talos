# 2026-10-15 — a node budget above the per-node ceiling is named, not silently clamped

**Context.** A check node's `max_fuel` was set to 250,000,000 with
`update_node_config`, which accepted it without a word. The run failed with
"the module consumed 50000000 instructions of a 50000000-instruction budget …
(configurable via WASM_FUEL_LIMIT or per-node max_fuel config)": the engine
clamps every node to `DEFAULT_MAX_FUEL_PER_NODE` (50M) before dispatch, so the
worker never saw the 250M, and its message pointed at the setting that had
just been raised. A whole collector re-run was spent learning that.

**Decided.**
- One home for the rule and its words: `talos_workflow_validation::fuel_above_ceiling`
  with `NODE_FUEL_CEILING` (= `talos_workflow_job_protocol::MAX_JOB_FUEL`, which the
  dispatcher already pins equal to the engine constant).
- `validate_workflow` warns, category `fuel-above-ceiling`, on the same baseline
  `resolve_node_max_fuel` uses (node `data.max_fuel` ?? `modules.max_fuel`).
- `update_node_config` (update_config / merge_config) and `add_node_to_workflow`
  carry the note at write time: the prose `Warning:` line and `max_fuel_note`
  (with `max_fuel_applied` on the update reply).
- `fuel_exhausted_message`, at a limit at or above `MAX_JOB_FUEL`, says the limit is the most
  any node is given instead of calling it configurable. The parsed substrings
  (`fuel exhausted`, `Current fuel limit: N`) are unchanged.

**Deliberately NOT done.**
- Refusing a budget above the ceiling at write time. Existing graphs may hold one, and
  a refusal would break their next unrelated edit; the value is harmless once named.
- Telling the worker what the node asked for. The request is clamped before it is signed
  onto the wire; carrying the unclamped value would be a new signed field for a message.

**Measured.** Nothing in production calls `set_max_fuel_per_node`, so the ceiling is
50M for every node on every deployment; the warning can say "every node".

**Stated limits.** The adaptive learned floor is also clamped to the ceiling; this does
not report that case (it is not authored). A deployment that lowers
`TALOS_WORKER_MAX_JOB_FUEL` below 50M still gets the "configurable" wording at its own
lower ceiling.
