# `graph_json` schema (v0)

This document describes the JSON wire shape the engine accepts at
[`ParallelWorkflowEngine::load_from_graph_json`][load-fn] and
[`ParallelWorkflowEngine::load_graph_from_json`][load-async-fn],
and returns from
[`WorkflowGraphStore::get_graph`][store-trait]. The shape derives
from React Flow's node/edge model so workflows authored in a
visual editor can be loaded directly.

## Choosing a construction path

Three paths produce graphs in this shape. Pick based on how the
workflow originates:

| Origin | Preferred path |
|---|---|
| **Authored in a visual editor** (React Flow, generated tooling) | Hand-written / exported JSON → `load_graph_from_json(&str)` |
| **Built programmatically from Rust code** | [`WorkflowGraphBuilder`][builder] → `load_graph_from_json(&str)` via `serde_json::to_string` |
| **Persisted graph store fetch** | `WorkflowGraphStore::get_graph` returns `String`; feed to `load_graph_from_json(&str)` |

The builder is the recommended in-process path because it gives you
type-checked construction against the live `SystemNodeKind` enum; the
engine's parser remains authoritative for what's accepted.

### Two parser entry points

Two public methods share a single authoritative parser — the
difference is only in input shape and whether post-parse async work
runs.

| Entry point | Input | Async follow-ups |
|---|---|---|
| `load_graph_from_json(&str)` (async) | JSON string | Yes — batch rate-limit pre-load and sub-workflow graph prefetch |
| `load_from_graph_json(&serde_json::Value)` (sync) | Parsed `Value` | None — use when rate-limit / sub-workflow caches are populated later or not needed |

Both accept the same node and edge shape (module nodes, system
nodes, reserved-key lifts, `execution_timeout_secs`, and full edge
handles). Both reject graphs with zero nodes with `LoadGraph`. Pick
the async variant when running the engine end-to-end; the sync one
fits sub-workflow dispatch sites that already hold a parsed `Value`
and don't need the async pre-loads.

## Stability

Pre-1.0, the shape is **additive-only**: new optional fields land in
0.x minor bumps; removing or re-typing an existing field bumps the
major version.

[load-fn]: https://docs.rs/talos-workflow-engine/0.2/talos_workflow_engine/struct.ParallelWorkflowEngine.html#method.load_from_graph_json
[load-async-fn]: https://docs.rs/talos-workflow-engine/0.2/talos_workflow_engine/struct.ParallelWorkflowEngine.html#method.load_graph_from_json
[store-trait]: https://docs.rs/talos-workflow-engine-core/0.2/talos_workflow_engine_core/trait.WorkflowGraphStore.html
[builder]: https://docs.rs/talos-workflow-engine/0.2/talos_workflow_engine/struct.WorkflowGraphBuilder.html

## Top-level shape

```jsonc
{
  "nodes": [ /* … node objects (see below) */ ],
  "edges": [ /* … edge objects (see below) */ ],

  // Optional overall cap; defaults to 300.
  "execution_timeout_secs": 300
}
```

Unknown top-level keys are ignored.

## Node object

```jsonc
{
  // Required. The engine parses this into the internal `Uuid` node
  // id. Any valid UUID v4 string works.
  "id": "550e8400-e29b-41d4-a716-446655440000",

  // Optional. When `type` is NOT a system-node kind string (see
  // below), the engine treats `type` as the module id that executes
  // at this node. Accepts either a bare UUID or the form
  // `module::<uuid>`.
  "type": "c8a7d9e4-…",

  // System-node kinds that the engine routes through built-in
  // handlers instead of dispatching to a module.
  //
  //   "foreach"       | "wait"            | "sub_workflow"   | "loop"
  //   "while_loop"    | "repeat_loop"     | "fan_in"         | "error_handler"
  //   "collect"       | "synthesize"      | "verify"         |
  //   "dispatch"      | "capability_dispatch" | "ops_alerts_digest"
  //
  // LLM-flavored kinds (gated by the `llm-primitives` feature, on by
  // default):
  //
  //   "agent_loop"    | "react_loop"      | "judge"          |
  //   "inline_judge"  | "ensemble"        | "confidence_gate"|
  //   "reflective_retry" | "llm_dispatch"
  //
  // Consumers with `llm-primitives` disabled see these kinds parsed
  // to `None` and the node is rejected at dispatch time.
  "kind": "foreach",

  // Optional. Free-form per-kind configuration. Shape depends on
  // `kind`. See "Per-kind `data`" below.
  "data": { /* … */ },

  // Optional per-node retry policy. Merged with the workflow-level
  // default if both are present.
  "retry_count":        2,
  "retry_backoff_ms":   500,
  "retry_condition":    "error_code == 429",     // expression
  "retry_delay_expression": "min(5000, base * 2)",

  // Optional control-flow hints. The engine stores these as
  // `__skip_condition` / `__continue_on_error` reserved keys on the
  // node's config; see `talos_workflow_engine_core::reserved_keys`.
  "skip_condition":       "upstream.skip",
  "continue_on_error":    true
}
```

Nodes whose `type` is NOT a resolvable module id (not a UUID, no
`data.moduleId` fallback) and whose `kind` is also absent are
silently skipped — the engine treats them as presentation-only
annotations, matching the React Flow frontend's behavior.

## Edge object

```jsonc
{
  // Required. The engine parses `source` / `target` as either the
  // node's UUID or a user-friendly label that matches some node's
  // `id`/label.
  "source": "n1",
  "target": "n2",

  // Optional. The engine uses this to distinguish output handles
  // for nodes that produce multiple outputs (e.g. `on_failure` /
  // `on_success`). Defaults to the source node's primary handle.
  "sourceHandle": "on_failure",

  // Optional. The engine uses this to match to a specific input
  // handle on the target.
  "targetHandle": "error",

  // Optional edge logic. Controls whether the edge fires based on
  // the source output. Defaults to `always`.
  //
  //   "always"                   — fire unconditionally
  //   {"condition": "expr"}     — fire when `expr` is truthy
  //   {"not_condition": "expr"} — fire when `expr` is falsy
  "logic": { "condition": "ok == true" }
}
```

## Per-kind `data` — selected shapes

The engine ignores unknown `data` keys; the shapes below document
the load-bearing subset. All numeric fields clamp at documented
bounds (e.g. `max_iterations` caps at 50 for agent loops).

### `foreach`
```jsonc
{ "input_path": "items", "output_handle": "element" }
```

### `wait`
```jsonc
{ "message": "Human approval required" }
```

### `sub_workflow`
```jsonc
{ "sub_workflow_id": "uuid", "timeout_secs": 30 }
```

### `loop`
```jsonc
// Re-dispatches a separate body node until `condition` returns false
// or `max_iterations` is hit. The body node id is read from
// `body_node_id` on the loop node's config at run time.
{ "max_iterations": 10, "condition": "iteration < 5" }
```

### `while_loop`
```jsonc
// Like `loop` but runs the body locally (no module dispatch). Each
// iteration wraps the previous output under `__loop_input`. Use when
// the body is pure data transformation and you want a single system
// node instead of a module + loop pair.
{ "condition": "cursor != null", "max_iterations": 10 }
```

### `repeat_loop`
```jsonc
// Iterates a fixed number of times with no condition evaluation. Pairs
// with a body node via edges (see `loop` for the re-dispatch pattern).
{ "count": 5 }
```

### `fan_in`
```jsonc
// Joins multiple upstream branches according to `join_mode`:
//   "All"         — wait for every branch (default when omitted)
//   "Any"         — release on the first completion
//   "Majority"    — wait for strict majority
//   {"N": 3}      — wait for exactly N branches
// Optional `aggregation_expr` transforms the joined outputs.
{ "join_mode": "All", "aggregation_expr": "sum" }
```

### `error_handler`
```jsonc
// Handles errors from upstream nodes. If `error_pattern` is set, only
// errors whose message matches (substring or regex, engine-defined)
// trigger this handler.
{ "error_pattern": "timeout|rate_limited" }
```

### `collect`
```jsonc
// Gathers every upstream branch's output into a single list on the
// node's output payload. No configuration — the `data` object is empty
// (or omitted). Pair with `synthesize` if you want to transform the
// collected list before downstream consumption.
{}
```

### `ops_alerts_digest`
```jsonc
// Controller-side read of the caller's ops-alerts triage store. Emits
// { available, digest: { active_by_severity, active_by_source,
//   new_last_24h, reopened_active }, top_active: [ ... ] } as the node
// output — the canonical feed for daily-brief compose nodes. Executes
// in the controller (no worker dispatch, no secrets); tenancy comes
// from the execution's resolved identity, never from this data object.
// When the store is unreachable the node emits { available: false }
// instead of failing the workflow.
{ "top_limit": 10 }   // active alerts included verbatim (1-25, default 10)
```

### `synthesize`
```jsonc
// Transforms a list of gathered outputs (typically produced by an
// upstream `collect` or fan-in) using an optional expression. When
// `synthesis_expr` is omitted the node forwards the list unchanged —
// useful as a labeled join point in the graph.
{ "synthesis_expr": "items | map(.score) | avg" }
```

### `verify`
```jsonc
{ "condition": "response.status == 200",
  "check_label": "http_ok",
  "on_failure": "error" }
```

### `judge` *(llm-primitives)*
```jsonc
{ "judge_workflow_id": "uuid",
  "rubric": "rate helpfulness 0-1",
  "pass_threshold": 0.7,
  "timeout_secs": 60 }
```

### `inline_judge` *(llm-primitives)*
```jsonc
// Evaluates a verdict expression in-process — no sub-workflow dispatch.
// The expression must return a verdict object (`{score, passed, reasoning,
// feedback}`); `pass_threshold`, when present, overrides the expression's
// own `passed` field for gating. Reach for `inline_judge` when the rubric
// is a one-line scoring expression; promote to `judge` once it grows its
// own prompt or model call.
//
// `verdict_expr` is required and must be non-empty; parsing rejects
// missing/empty expressions at load time.
{ "verdict_expr": "{score: input.confidence, passed: input.confidence > 0.5}",
  "pass_threshold": 0.5 }
```

### `ensemble` *(llm-primitives)*
```jsonc
{ "child_workflow_id": "uuid",
  "count": 3,
  "consensus": "majority_vote",
  "judge_workflow_id": "uuid",
  "timeout_secs": 60 }
```

### `confidence_gate` *(llm-primitives)*
```jsonc
{ "threshold": 0.7,
  "confidence_path": "__confidence__",
  "on_low_confidence": "pause" }
```

### `llm_dispatch` *(llm-primitives)*
```jsonc
{ "classifier_workflow_id": "uuid",
  "routes": { "support": "uuid", "billing": "uuid" },
  "fallback_workflow_id": "uuid",
  "timeout_secs": 60 }
```

### `reflective_retry` *(llm-primitives)*
```jsonc
{ "child_workflow_id": "uuid",
  "reflection_workflow_id": "uuid",
  "max_retries": 2,
  "timeout_secs": 60 }
```

### `agent_loop` *(llm-primitives)*
```jsonc
// ReAct-style loop that re-dispatches `body_workflow_id` with the
// accumulated history on each iteration. Stops on an explicit terminal
// output or when `max_iterations` is hit (hard cap: 50).
{ "body_workflow_id": "uuid",
  "max_iterations": 10,
  "inject_history": true,
  "timeout_secs": 60 }
```

### `react_loop` *(llm-primitives)*
```jsonc
// Reasoning + acting variant. Shape is identical to `agent_loop` — the
// distinction is handler behavior, which may diverge in future releases.
// Use `agent_loop` unless you specifically want the ReAct variant.
{ "body_workflow_id": "uuid",
  "max_iterations": 10,
  "inject_history": true,
  "timeout_secs": 60 }
```

### `dispatch`
```jsonc
{ "dispatch_expression": "classifier.output.route",
  "timeout_secs": 30 }
```

### `capability_dispatch`
```jsonc
{ "required_capabilities": ["llm", "rag"], "timeout_secs": 30 }
```

## Reserved `__`-prefixed keys

The engine reads and writes a set of reserved keys on node input and
output payloads. See
[`talos_workflow_engine_core::reserved_keys`](https://docs.rs/talos-workflow-engine-core/0.2/talos_workflow_engine_core/reserved_keys/index.html)
for the authoritative list. Consumer-authored module output must
not shadow these — the engine strips them from user-visible output
where documented, and reading them back has undefined results.

## Versioning

The workspace is pre-1.0. The schema above is v0. Until 1.0:

* New optional fields are backwards-compatible.
* New system-node kinds are backwards-compatible (unknown kinds
  parse to `None` and are rejected at dispatch).
* Removing or changing a field's type bumps the major version.
* New LLM-flavored kinds ship behind the `llm-primitives` feature.
