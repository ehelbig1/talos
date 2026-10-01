# 2026-10-01 — `test_module` runs under the limit a node would set

**Context.** `test_module` held every run to the module row's `max_fuel` and
had no way to change it. Its exhaustion error said the limit was
"configurable via … per-node max_fuel config", which the tool ignored.

**Measured on the reference deployment.** The installed `LLM Inference` copy
carries a 1,404,000 limit; a 10 KB prompt runs out before the model is
called, while every workflow node that uses the module sets `max_fuel` to
8–10 M (11 nodes). So the module could not be rehearsed with a realistic
prompt at all; evaluating one took a throwaway workflow. A new module with a
too-low computed limit had to be recompiled just to try a larger input.

**Change.** `resolve_test_fuel_limit(config, module_max_fuel)` (one home, in
`talos-mcp-handlers/src/sandbox.rs`): `max_fuel` in the run's `config`
overrides the module row, in either direction, capped at
`talos_workflow_engine::DEFAULT_MAX_FUEL_PER_NODE` — the same key and the
same ceiling a workflow node gets. The reply's `fuel` block gains
`limit_source` (`module` | `node_config`), a `limit_note` when the value was
capped, and a `limit_hint` when a run exhausts the module's own limit.

**Decided.** A `max_fuel` that is present but not a positive whole number is
refused (`-32602`), not ignored: the caller asked for a limit and would
otherwise read a result measured against another one. (The engine ignores a
non-numeric value at dispatch; a rehearsal can afford to be stricter.)

**Bounds.** The cap is the engine ceiling; wall-clock is still bounded by
`timeout_secs` (≤ 120) and the epoch ticker. No authorization change: the
module-visibility, actor-ownership, tier, egress and write-ceiling gates run
as before.

**Stated limits.** The adaptive-fuel learned floor is not modelled (it
depends on a node's own history), so a rehearsal can still run under a lower
limit than the node will get. The handler wiring is not driven by a test —
the resolver, the reply and the tool description are; the live call after
deploy is the wiring's check.
