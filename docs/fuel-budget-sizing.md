# Sizing a node's fuel budget

Written 2026-08-17, after `pa-read-later-digest/digest` ran for five weeks on
a budget that could not accommodate its own configured maximum output and
failed two of its four scheduled runs. Everything below is what that
investigation had to reconstruct from first principles because it was written
down nowhere.

## How the effective ceiling is resolved

One decision point, `ParallelWorkflowEngine::resolve_node_max_fuel`
(`talos-workflow-engine/src/engine_config.rs`):

```
baseline = graph-JSON  data.max_fuel   (per node)
        ?? modules.max_fuel            (shared by every consumer of that module)

effective = max(baseline, learned_adaptive_ceiling)   -- adaptive is a FLOOR
                .min(engine.max_fuel_per_node)        -- 50,000,000 default
```

Three consequences worth stating explicitly:

* **`modules.max_fuel` is shared.** Raising it to fix one node raises it for
  every override-less consumer of that module. Prefer a node-scoped
  `data.max_fuel`; the blast radius is then one node.
* **A non-numeric `data.max_fuel` is silently ignored.** The engine reads it
  with `serde_json::Value::as_u64`, so `"8000000"` (a string) or `8e6` (a
  float) is `None` and the node falls back to the module default. There is no
  warning.
* **Adaptive fuel can only raise, never lower.** It is a guard, not a
  governor. Kill switch: `TALOS_ADAPTIVE_FUEL=0`.

## Adaptive fuel does not cover low-cadence workflows

`talos-engine/src/adaptive_fuel.rs` requires `MIN_SAMPLES = 5` completed runs
inside `WINDOW_DAYS = 30` — a run roughly every six days. **Every weekly
workflow is structurally outside the guard**, and so is every node that has
run fewer than five times for any other reason.

Two properties compound:

* Only **completed** runs write an `execution_cost_rollup` row, so a
  fuel-exhaustion failure produces **no sample**. A node that flaps cannot
  accumulate the evidence that would earn it the raise that would fix it.
* Census on the live database, 2026-08-17: **145 of 202** distinct
  (workflow, node) pairs with fuel history in the window sit below the
  sample floor. The guard covers 57.

The two nodes that make this concrete both run the same `LLM Inference`
module off the same 1,404,000 default:

| Node | Samples | What adaptive did |
|---|---|---|
| `content-pipeline-weekly/weekly_idea` | 6 | Raised 1,404,000 → 2,048,086 on 2026-08-03 |
| `pa-read-later-digest/digest` | 2 | Nothing. Stayed at 1,404,000 and failed twice. |

`weekly_idea` cleared the floor only because scheduler restart catch-ups
inflated its run count; #634 removed that masking. **Do not rely on adaptive
fuel to catch an under-provisioned weekly node — set the budget yourself.**

### Being inside the guard is not the same as being safe

The sample floor is the *cadence* half of the problem. The other half is
**survivorship**, and it bites nodes that clear the floor by a wide margin.

`pa-ask-email/fetch` has **3,627 samples** in the window — 725× the floor — and
still failed **49 times** with `Current fuel limit: 1100000` on 2026-07-22. On
that same day 99 of its runs succeeded, at ceilings from 1.1M up to 24.46M,
with peak *surviving* consumption of 2,262,361 — twice the ceiling the failures
died under.

The guard learns from the runs that fit. A run that exceeds the ceiling is the
clearest possible evidence that the ceiling is too low, and it is exactly the
run that gets deleted from the sample. `adaptive_ceiling(p95, max)` is
therefore computed over a right-censored distribution, biased low precisely
where demand is highest. Across the whole database, 66 fuel-exhaustion failures
have occurred across 7 workflows; **none of them contributed a single sample**.

So: a high sample count tells you the guard is *running*, not that the number
it learned covers your worst payload.

## The cost multiplier that does not appear in `input_data`

If a node's capability world is **memory-eligible** — anything other than the
pure-egress worlds (`http` / `network` / `messaging`), so `secrets-node` and
`agent-node` included — the engine injects `__actor_context__` into its input
when grounded memory is on (`ENABLE_SMART_MEMORY_CONTEXT`, default on). That
is **up to `SMART_MEMORY_CONTEXT_BYTE_BUDGET` bytes (12,000 default)** on top
of the upstream payload, and it is **not visible in
`module_executions.input_data`**.

So a `secrets-node` sized from its recorded input alone is sized short.
Budget for the injection, or set `needs_memory: false` on a node that does not
consume memory.

## Raising fuel does not bound the payload

Fuel is a **resource limit**. Raising one is a security change as much as a
performance one, and it does not cap anything upstream of the module.

* `WASM_MAX_INPUT_BYTES` defaults to **1,000,000** — roughly 100× looser than
  what a typical LLM node's fuel budget tolerates. Payload growth therefore
  surfaces as *fuel exhaustion after a full LLM generation has already been
  paid for*, not as a clean input rejection. On `digest` each failure burned a
  complete ~28 s Ollama call before dying in post-processing.
* **`readlater-fetch` truncates `snippet` to 220 chars but does not truncate
  `Subject` or `From` at all.** Both are attacker-influenceable by anyone who
  can get mail into the inbox; the user applying the `[To Read]` label is the
  only gate. The impact is self-DoS of the user's own digest, not
  exfiltration — but a longer budget widens the window rather than closing it.
  Byte-level caps on those two fields are the actual fix and are **not done as
  of 2026-08-17**.
* Note `snippet`'s cap is `.chars().take(220)`, i.e. up to ~880 bytes for
  4-byte code points, not 220 bytes.

When you raise a budget, state what still bounds it: the 50M engine ceiling,
the per-step wall-clock timeout, and — if populated — the actor's
`actor_budget_policies` (`max_fuel_per_execution`, `max_fuel_per_hour`,
`fuel_budget_daily`) and `tenant_quotas.max_fuel_per_execution`. All of those
are NULL/empty for the PA actor today, which means **no budget is currently
backstopping a mis-set node ceiling**.

## Where the real numbers live

* **`execution_cost_rollup`** — authoritative per-node `fuel_consumed`,
  `max_fuel` (the ceiling the worker actually enforced, from the
  `__fuel_limit__` stamp), `wall_time_ms`. Written by
  `ControllerNodeHook::on_node_completed`. **Only for completed runs.**
* **`module_executions.fuel_consumed`** — populated from `__fuel_consumed__`
  by `record_completed` as of 2026-08-17. Before that it was a dead column:
  0 of 25,213 rows written, because its only writer
  (`ModuleExecutionService::complete_execution`) is reachable only through
  `complete_execution_best_effort`, which has no callers. **The 25,213
  historical rows stay NULL** — a NULL here means "nobody wrote it", not
  "no fuel was used".
* **`get_execution_trace`** (MCP) — per-node fuel, ceiling and
  `utilization_pct` for one execution. The fastest way to see how close a
  node is running to its limit.

A node sitting above ~80% utilisation on a full payload has no headroom and
should be treated as already failing.

## The two checks that now enforce this page

Both were added because everything above was true, written down, and enforced
by nothing.

### 1. `TalosFuelHeadroomLow` — a running node with no headroom

`talos_fuel_high_utilisation_nodes` counts `(workflow, node)` pairs whose
**peak** `fuel_consumed` over the last 30 days is at or above **80%** of the
ceiling a worker **most recently enforced** for them. Test executions are
excluded. Published every 5 minutes by
`controller::bootstrap::background::publish_fuel_utilisation`.

**It has no sample floor and must never grow one.** That is the whole reason it
catches what nothing else did: `digest` had two runs, `MIN_SAMPLES` is 5, and
`get_fuel_usage_report`'s `min_executions` defaults to 3. A floor here would
make this the third surface blind to the same node.

Three properties worth knowing before you read the number:

* **The names are not in the metric.** Node labels are author-supplied, so a
  per-node label is unbounded cardinality. Look in the controller WARN log
  (`target=talos_fuel`, `event_kind=fuel_headroom_low`) or at
  `get_fuel_usage_report` → `high_utilisation_nodes`.
* **Raising the budget does not clear it immediately.** The ceiling read is the
  limit a worker *enforced*, so a config change lands only after the node next
  runs — up to a week for a weekly workflow. An unexercised budget is not
  evidence.
* **0 is ambiguous on its own**, which is why
  `talos_fuel_utilisation_observed_nodes` publishes the denominator and
  `TalosFuelHeadroomDetectorBlind` fires when the detector observes nothing
  while executions are completing.

### 2. `validate_workflow` — a budget that cannot cover its own MAX_TOKENS

A node declaring `MAX_TOKENS` whose effective ceiling
(`data.max_fuel ?? modules.max_fuel`) is below
`3,000 × MAX_TOKENS + 40 × context_bytes` gets a `fuel-sizing` **warning** at
authoring time, at `publish_version`, and after `hot_update_module`.

This is the dead zone no estimator reaches: a node wrong on its **first** run
has no history to learn from. `digest` was under-provisioned from execution #1.

The `3,000` is calibrated, not assumed: every node an author has deliberately
sized sits between **4,444** and **11,429** fuel per configured token, and
pre-#642 `digest` sat at **1,002**. Nothing lies between, so any constant
inside that band gives identical verdicts on every node that exists.

The `40 × context_bytes` term is the `__actor_context__` allowance and is the
weakest number in the check — there is no measurement of the fuel cost of an
injected byte anywhere in the platform. It is deliberately **not
load-bearing**: removing it entirely changes no verdict on the current fleet
(pinned by a test). It exists so the check does not pretend the injection is
free.

**What the check does NOT claim.** It is a floor. Clearing it does not mean a
node is correctly sized — only that it is not obviously wrong. The runtime
detector above is the surface for everything above the floor, and the two are
complementary: the detector needs history and this needs none.

## Reading a fuel-exhaustion error

The message (`talos_worker_runtime::runtime::fuel_exhausted_message`) reports
consumption and limit as **distinct** quantities, and states the requirement
as unknown:

```
WASM fuel exhausted: the module consumed 1404000 instructions of a
1404000-instruction budget and did not finish, so its actual requirement is
UNKNOWN — only that it exceeds 1404000. …
Current fuel limit: 1404000 (configurable via WASM_FUEL_LIMIT or per-node
max_fuel config).
```

Consumption equals the limit at exhaustion *by construction* — the module
drained the budget. **That number is not a measurement of demand.** Nothing in
the system observed how much more the module needed; the trap stopped it
mid-instruction. Sizing a new budget as "the number in the error, plus a bit"
is exactly the mistake this wording exists to prevent — and before 2026-08-17
the message printed the limit into both slots, so `exhausted after 1404000
instructions` *was* the limit repeated, reading as a measurement it never was.

Size from the node's own configured maximum instead: for an LLM node, from
`MAX_TOKENS` and the observed cost of a known-good completion. `digest`
consumed 1.36M on a completion roughly a third of its `MAX_TOKENS: 1400`, so
its configured maximum output alone puts the requirement near 4M before the
`__actor_context__` injection is counted.

## Checklist for a new or resized budget

1. Is the value **node-scoped** (`data.max_fuel`), or does it move a shared
   `modules.max_fuel`? Name every other consumer if the latter.
2. Is the node's capability world memory-eligible? Add the
   `__actor_context__` budget.
3. Derive from the node's **configured maximum** (`MAX_TOKENS`, item caps),
   not from the last observed run — the last run may be the small-payload one.
4. State the ceiling that still bounds the new value, and whether any
   per-actor or per-tenant budget interacts.
5. Does the workflow run often enough for adaptive fuel to ever help? If it
   runs weekly, it does not. The number you set is the number it lives with.
6. Run `validate_workflow`. A `fuel-sizing` warning means the budget cannot
   cover the node's own configured maximum — fix that before looking at
   anything else.
7. After it has run, check `get_fuel_usage_report` →
   `high_utilisation_nodes`. Step 6 is a floor and cannot tell you whether the
   number holds against real inputs.
