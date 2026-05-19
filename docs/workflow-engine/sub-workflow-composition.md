# Composing sub-workflows: Judge, Ensemble, AgentLoop

Five `SystemNodeKind` variants delegate their actual work to another
workflow:

* `SubWorkflow` — the generic "invoke graph X" form.
* `Judge` — score an upstream output via an LLM-as-judge graph.
* `Ensemble` — run N copies of a child graph and consolidate.
* `AgentLoop` / `ReActLoop` — run a body graph until it signals
  `finished` or hits an iteration cap.
* `ReflectiveRetry` — run a child; on failure, run a reflection graph
  and retry.

This guide covers what shape each child workflow should take, where its
graph lives, and the engine-side conventions you have to honor for the
parent variant to read its output correctly.

## Where child graphs live

The engine resolves child graphs through the
[`WorkflowGraphStore`][gs] trait you wired via
[`set_graph_store`][sgs]. At run-start, it batch-fetches every workflow
id referenced by `Judge`, `Ensemble`, `AgentLoop`, `ReActLoop`,
`ReflectiveRetry`, and `LlmDispatch` nodes in one round-trip — the
contract is "given a UUID, return the graph JSON." Persist child
graphs the same way you persist top-level ones; they are not special at
the storage layer.

For tests, [`InMemoryWorkflowGraphStore`][ims] from
`talos-workflow-engine-test-utils` lets you seed by id:

```rust
let store = Arc::new(
    InMemoryWorkflowGraphStore::new()
        .with_graph(judge_workflow_id, judge_graph_json)
);
engine.set_graph_store(store);
```

## `Judge`: parse a verdict shape

Parent variant:

```rust
SystemNodeKind::Judge {
    judge_workflow_id: Uuid,
    rubric: String,
    pass_threshold: Option<f64>,
    timeout_secs: u64,
}
```

The engine runs the judge sub-workflow, collapses its outputs, and
parses a [`JudgeVerdict`][jv]. The contract: **the collapsed output
must be a JSON object with these four fields**:

```json
{
  "score":     0.0..=1.0,
  "passed":    true,
  "reasoning": "...",
  "feedback":  "..."
}
```

Missing or wrong-typed fields fall back to defaults (`0.0` / `false` /
`""`) and the engine logs a `malformed_field_count` warning so you can
spot a broken judge in production.

### The minimal judge graph

A judge is typically a one-node workflow whose module calls an LLM with
the parent's output as input plus the rubric as a system prompt. The
module returns the verdict shape directly; the engine consumes it.

```rust
let judge_module = Uuid::new_v4(); // your llm-judge module
let judge_graph = WorkflowGraphBuilder::new()
    .add_module("score", judge_module, Some(json!({
        "model": "claude-haiku-4-5-20251001",
        "rubric_template": "You are scoring {{ candidate }} against this rubric: {{ rubric }}",
        "output_schema": {"score": "f64", "passed": "bool", "reasoning": "string", "feedback": "string"}
    })))
    .build()?;
```

Persist `judge_graph` to your `WorkflowGraphStore` with a UUID, then
reference that UUID in the parent's `Judge` variant.

### Tip: validate the verdict shape early

Wire an `OutputSanitizer` that hard-rejects judge outputs missing any
of the four fields — the engine's default behavior is to log and
continue with defaults, which is robust but quiet. For a judge whose
verdicts gate downstream behavior (`pass_threshold` branching), you
want the loud signal.

## `Ensemble`: design for consolidation

Parent variant:

```rust
SystemNodeKind::Ensemble {
    child_workflow_id: Uuid,
    count: u32,
    consensus: String,         // executor-defined label
    judge_workflow_id: Option<Uuid>,
    timeout_secs: u64,
}
```

The engine invokes `child_workflow_id` `count` times in parallel, then
applies the `consensus` strategy to consolidate. Built-in strategies
the executor recognises:

* `"majority_vote"` — pick the modal output. Suitable for
  classification.
* `"best_of_n"` — invoke the optional `judge_workflow_id` on each
  candidate, pick the highest-scored.
* Other labels delegate to the executor's strategy registry — see your
  build's `ConsensusStrategy` impls.

### Designing the child graph

Every child invocation gets a fresh execution id, a clean copy of the
parent's input, and no shared state. Three rules:

1. **Stateless.** A child invocation must not depend on what other
   replicas produced. If your "ensemble" is really a sequence (each
   replica reads the previous one), use `AgentLoop`, not `Ensemble`.
2. **Same output shape.** Consensus needs to compare apples to apples.
   If one replica returns `{"answer": "yes"}` and another returns
   `{"result": "yes"}`, majority vote sees two distinct outputs.
3. **For `best_of_n`, return JSON the judge can score.** The engine
   feeds each candidate through the judge as `candidate` and reads
   `score` back.

## `AgentLoop` / `ReActLoop`: the iteration contract

Parent variants:

```rust
SystemNodeKind::AgentLoop {
    body_workflow_id: Uuid,
    max_iterations: u32,
    inject_history: bool,
    timeout_secs: u64,
}

SystemNodeKind::ReActLoop { /* same fields */ }
```

The engine invokes `body_workflow_id` once per iteration up to
`max_iterations`, with three special inputs injected:

| Key | When | Shape |
|---|---|---|
| `__agent_iteration__` | Every iteration | `u64` (1-indexed) |
| `__agent_history__` | When `inject_history: true` and iteration > 1 | Array of prior iteration outputs |
| (parent inputs) | Every iteration | Whatever the parent node received, with `__`-prefixed keys stripped |

### Stopping the loop

The body signals completion by returning JSON with **either**:

* `{"finished": true, ...}`, or
* `{"action": "FINISH", ...}` (case-insensitive).

When neither is set and the iteration cap is reached, the engine
returns the last iteration's output with no `finished` flag —
downstream nodes can detect this if they care.

### History window

By default the engine keeps the last 20 iteration outputs in the
sliding window injected as `__agent_history__`. Configure per-engine
via [`set_agent_loop_max_history`][almh]; the chosen value applies to
every `AgentLoop` and `ReActLoop` node in the graph (and any
sub-workflow loops dispatched through the same `AdapterSet`). Larger
windows raise context cost; shorter windows lose context. Default 20
is calibrated for ReAct chains with ~5KB outputs per step.

### Designing the body graph

The body is a workflow like any other. Common shapes:

* **Single node** — one module that does "reason about
  `__agent_history__`, decide next action, return result." The
  simplest agent body.
* **Two nodes** — a planner + a tool runner, joined by a `Synthesize`.
* **Many nodes** — a full ReAct decision graph. The body itself can
  contain `Verify` / `ConfidenceGate` / sub-workflow nodes.

Whatever you build, the body **must** return a JSON object containing
`finished` or `action` for the loop to terminate cleanly.

## `ReflectiveRetry`: feedback-driven retry

Parent variant:

```rust
SystemNodeKind::ReflectiveRetry {
    child_workflow_id: Uuid,
    reflection_workflow_id: Uuid,
    max_retries: u32,
    timeout_secs: u64,
}
```

Two child workflows compose:

1. The engine runs `child_workflow_id`. If it succeeds (no `__error`),
   that's the output.
2. On failure (or `__error: true` in the output), the engine runs
   `reflection_workflow_id` with the failed output as input. The
   reflection's output becomes additional input on the next attempt.
3. Repeat up to `max_retries`.

### The reflection contract

The reflection workflow's output is merged into the next attempt's
input under the key `__reflection_feedback__`. Treat your child graph
as receiving input that **may or may not** carry that key — first
attempt has none, retries do.

```rust
// Inside the child module:
let prior_feedback = input.get("__reflection_feedback__").and_then(|v| v.as_str());
if let Some(feedback) = prior_feedback {
    // Adjust strategy based on what the reflector said went wrong.
}
```

## When a sub-workflow feels like ceremony

Two valid escape hatches:

1. **`Synthesize` with an inline expression.** Use this when the
   "judge" logic is really a one-line scoring function. Wire an
   `ExpressionEvaluator` (`rhai`-backed in production) and let
   `synthesis_expr` do the work. Faster than authoring a separate
   workflow when the verdict is computable from upstream fields
   directly.
2. **`Verify` for boolean gates.** When `Judge` would only feed a
   pass/fail decision into routing logic, `Verify` is the right
   primitive — single inline condition, branch on failure handle.
   `pass_threshold` against a sub-workflow score is overkill if the
   condition is `confidence > 0.8`.

Pick the sub-workflow path when the judge / ensemble logic is itself
worth versioning, observing, and reusing — that's what graphs are for.
Pick `Synthesize` / `Verify` when it's a one-liner.

## Calling judges outside a graph

If you're embedding the engine in a CLI, an HTTP handler, or any
other context where you want to score a single value without
authoring a wrapper workflow, [`ParallelWorkflowEngine::dispatch_judge`][dj]
and [`dispatch_inline_judge`][dij] are public entry points. Same
sub-workflow lookup, same verdict shape, same envelope as the
in-graph dispatch path — the scheduler simply calls these methods
when it hits a `Judge` / `InlineJudge` node, and so can you. Useful
for:

- One-off content scoring with no surrounding workflow.
- MCP handlers / HTTP endpoints that take `(content, rubric)` and
  return a verdict.
- Batch tools that re-score a corpus of historical outputs against a
  new rubric.

Skip these when you have a workflow that genuinely composes — put a
`Judge` node in the graph and let the scheduler dispatch it. The
direct calls are an embedding affordance, not an alternative
authoring model.

[dj]: https://docs.rs/talos-workflow-engine/0.2/talos_workflow_engine/struct.ParallelWorkflowEngine.html#method.dispatch_judge
[dij]: https://docs.rs/talos-workflow-engine/0.2/talos_workflow_engine/struct.ParallelWorkflowEngine.html#method.dispatch_inline_judge

[gs]: https://docs.rs/talos-workflow-engine-core/0.2/talos_workflow_engine_core/trait.WorkflowGraphStore.html
[sgs]: https://docs.rs/talos-workflow-engine/0.2/talos_workflow_engine/struct.ParallelWorkflowEngine.html#method.set_graph_store
[ims]: https://docs.rs/talos-workflow-engine-test-utils/0.2/talos_workflow_engine_test_utils/memory/struct.InMemoryWorkflowGraphStore.html
[jv]: https://docs.rs/talos-workflow-engine/0.2/talos_workflow_engine/struct.JudgeVerdict.html
[almh]: https://docs.rs/talos-workflow-engine/0.2/talos_workflow_engine/struct.ParallelWorkflowEngine.html#method.set_agent_loop_max_history
