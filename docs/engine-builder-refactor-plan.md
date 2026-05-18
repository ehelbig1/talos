# EngineBuilder::for_workflow — refactor plan (Phase B, target ~r227–r230)

**Status:** Plan complete; not yet executed. Reconnaissance done by a Plan subagent on 2026-04-28 from main @ f2a1d97 (r225 shipped).

**Why this exists:** Every controller path that runs a workflow constructs a `ParallelWorkflowEngine` from scratch with slightly different setter calls. The drift caused Task #402 (scheduler missing `set_execution_timeout_secs`) and likely two latent bugs surfaced by this audit (see "Latent bugs" below). A single canonical builder would prevent the next regression of this class.

## Site inventory (20 total)

Every controller site that calls `crate::engine::builder::build_controller_engine` for dispatch.

| # | Site | Purpose |
|---|---|---|
| 1 | `controller/src/scheduler.rs:499-575` | Cron-triggered workflow run |
| 2 | `controller/src/routes.rs:118-127` | Resume in-flight execution after restart |
| 3 | `controller/src/mcp/executions.rs:976-996` | replay_execution |
| 4 | `controller/src/mcp/executions.rs:2061-2082` | enqueue_workflow background loop |
| 5 | `controller/src/mcp/executions.rs:2518-2531` | replay_execution_with_input |
| 6 | `controller/src/mcp/executions.rs:4535-4552` | retry_execution |
| 7 | `controller/src/mcp/actor.rs:3503-3518` | handoff_to_actor |
| 8 | `controller/src/mcp/advanced.rs:3194-3214` | trigger_continuation_workflow |
| 9 | `controller/src/mcp/workflows.rs:3723-3764` | trigger_workflow |
| 10 | `controller/src/mcp/workflows.rs:4183-4242` | test_workflow_draft |
| 11 | `controller/src/mcp/workflows.rs:5178-5205` | call_workflow |
| 12 | `controller/src/mcp/workflows.rs:6070-6094` | bulk_trigger_workflow |
| 13 | `controller/src/mcp/workflows.rs:6449-6472` | trigger_workflow_as_actors |
| 14 | `controller/src/mcp/workflows.rs:6913-6991` | test_workflow |
| 15 | `controller/src/mcp/secrets.rs:1017-1029` | rotate_secret dependent-workflow verification |
| 16 | `controller/src/api/schema/workflows/mutations.rs:239-395` | GraphQL trigger_workflow |
| 17 | `controller/src/api/schema/workflows/mutations.rs:686-808` | GraphQL resume_workflow |
| 18 | `controller/src/api/schema/workflows/mutations.rs:1491-1502` | GraphQL test_workflow |
| 19 | `controller/src/api/schema/executions/mutations.rs:135-166` | GraphQL retry_execution |
| 20 | `controller/src/webhooks/mod.rs:1205-1233` | webhook-triggered workflow |

## Knob matrix

✓ unconditional, ◐ conditional, ✗ omitted-but-applicable, — N/A.

| # | Site | wf_id | actor | ctx | timeout(graph) | timeout(override) | dry | graph | eff_actor |
|---|---|---|---|---|---|---|---|---|---|
| 1 | scheduler | ✓ | ◐ | ◐ | ◐ | — | — | ✓ | — |
| 2 | routes resume | ✗ | ✗ | ✗ | ✗ | — | — | ✓ | — |
| 3 | replay_execution | ✗ | ✗ | ✗ | ◐ | — | — | ✓ | — |
| 4 | enqueue_workflow | ✗ | ✗ | ✗ | ◐ | — | — | ✓ | — |
| 5 | replay_execution_with_input | ✗ | ✗ | ✗ | ✗ | — | — | ✓ | — |
| 6 | retry_execution | ✗ | ✗ | ✗ | ◐ | — | — | ✓ | — |
| 7 | handoff_to_actor | ✗ | ✓ | ✗ | ✗ | — | — | ✓ | — |
| 8 | trigger_continuation | ✗ | ✗ | ✗ | ◐ | — | — | ✓ | — |
| 9 | trigger_workflow | ✗ | ◐ | ◐ | ◐ | — | ◐ | ✓ | ✓ |
| 10 | test_workflow_draft | ✗ | ◐ | ◐ | ◐ | — | — | ✓ | ✓ |
| 11 | call_workflow | ✗ | ◐ | ✗ | — | ✓(arg) | ◐ | ✓ | — |
| 12 | bulk_trigger_workflow | ✗ | ◐ | ✗ | ◐ | — | — | ✓ | — |
| 13 | trigger_workflow_as_actors | ✗ | ✓ | ✗ | ◐ | — | — | ✓ | — |
| 14 | test_workflow | ✗ | ◐ | ◐ | — | ✓(600 hardcoded) | ◐ | ✓ | ✓ |
| 15 | secrets verify | ✗ | ✗ | ✗ | — | ✓(30 hardcoded) | — | ✓ | — |
| 16 | gql trigger_workflow | ✗ | ◐ | ✗ | ✗ **BUG** | — | ✗ | ✓ | — |
| 17 | gql resume_workflow | ✗ | ✗ | ✗ | ✗ | — | — | ✓ | — |
| 18 | gql test_workflow | ✗ | ✗ | ✗ | ✗ | — | — | ✓ | — |
| 19 | gql retry_execution | ✗ | ✗ | ✗ | ✗ | — | — | ✓ | — |
| 20 | webhook trigger | ✗ | ◐ | ✗ | ✗ **BUG** | — | — | ✓ | — |

## Latent bugs surfaced

1. **Sites #16 (GraphQL trigger) and #20 (webhook trigger) miss the graph-JSON timeout** — same bug class r225 fixed for the scheduler. Reproduces today on a workflow with `execution_timeout_secs` in graph_json triggered via either path.
2. **`set_workflow_id` is called ONLY by scheduler.** Every other site falls back to `execution_id` for analytics rollups (`engine_completion.rs:263, 522`). Per-workflow rollups in `NodeCompletionContext` are silently bucketed per-execution everywhere except scheduled runs.
3. **Resume paths strip every setter.** `routes.rs:118`, `mutations.rs:686, 1491`, `executions/mutations.rs:135` all call `load_graph_from_json` only — no actor, no timeout, no actor_context. A resumed execution may run with different tier ceilings or longer timeouts than the original.
4. **Asymmetric "effective_actor" pattern.** Sites #9, #10, #14 use `arg.or(wf_record.actor_id)`; sites #11, #12 use only `wf_record.actor_id`. Possibly intentional, possibly drift — needs product decision before refactor.

## Key engine behavior to verify before refactor

`load_graph_from_json` ALREADY reads `execution_timeout_secs` from the graph and writes it into the engine via `parse_graph_document` (`engine.rs:1881`). If true, the manual `if Ok(parsed) … set_execution_timeout_secs(timeout)` extraction at 10+ call sites is **redundant** — the engine does it on graph load. **Action: write a focused test before refactor to confirm. If confirmed, `TimeoutPolicy::FromGraphJson` becomes a no-op and the migration shrinks substantially.**

## Proposed API

In `controller/src/engine/builder.rs`:

```rust
pub struct EngineOpts {
    pub workflow_id: Uuid,                  // required
    pub effective_actor_id: Option<Uuid>,   // None = anonymous
    pub actor_context: Option<JsonValue>,
    pub timeout: TimeoutPolicy,
    pub dry_run: bool,
    pub graph: GraphSource,
}

pub enum TimeoutPolicy {
    FromGraphJson,                          // honor graph's value (default)
    Override(u64),                          // force, ignore graph
    EngineDefault,                          // skip set_execution_timeout_secs
}

pub enum GraphSource {
    Json(String),                           // call load_graph_from_json
    SkipLoad,                               // for execute_subworkflow_graph paths
}

impl EngineOpts {
    pub fn for_run(workflow_id: Uuid, graph_json: String) -> Self { ... }
    pub fn with_effective_actor(self, arg: Option<Uuid>, default: Option<Uuid>) -> Self { ... }
    pub fn with_actor_context(self, ctx: Option<JsonValue>) -> Self { ... }
    pub fn with_dry_run(self, dry: bool) -> Self { ... }
    pub fn with_timeout_override(self, secs: u64) -> Self { ... }
    pub fn with_timeout_engine_default(self) -> Self { ... }
}

pub async fn for_workflow(
    state: &AppState,
    user_id: Uuid,
    opts: EngineOpts,
) -> Result<Engine, BuildError> {
    // 1. build_controller_engine(registry, secrets_manager, user_id)
    // 2. set_workflow_id(opts.workflow_id) — always
    // 3. if Some(actor_id) → state.actor_repo.apply_actor_to_engine (log+continue on Err)
    // 4. if Some(ctx) → set_actor_context
    // 5. match opts.timeout
    // 6. if dry_run → set_dry_run(true)
    // 7. match opts.graph
}
```

**Critical contract:** `apply_actor_to_engine` is fail-closed (stamps Tier1 on error and logs). The builder MUST log + continue on Err, NOT bubble — preserves the security stance. Document this prominently or a future maintainer will "fix" the swallowed error and break tier-1 enforcement.

## Migration plan (8 PRs, target r226 → r230)

| PR | Scope | Risk | Notes |
|----|-------|------|-------|
| 0 | Land API + mock-engine test infra. No call-site changes. | Low | Foundation. Mock engine is needed because most call sites have NO existing test coverage. |
| 1 | Migrate scheduler. | Low | Canonical reference. Add integration test for graph-JSON timeout enforcement. |
| 2 | Migrate replay/retry/enqueue/continuation cluster (sites #3, #4, #6, #8). | Low-Medium | Mechanical; near-identical bodies. |
| 3 | Migrate webhook + GraphQL trigger (sites #16, #20). **Fixes the timeout regression.** | Medium | Behavior change — call out in PR description. |
| 4 | Migrate override-timeout sites (#11, #14, #15). | Low | One commit per site for bisectability. |
| 5 | Migrate actor-context-rich paths (#9, #10, #14). | Highest | Most user traffic; most knobs. Ship one of three per PR if conservative. |
| 6 | Migrate handoff + bulk fan-out (#7, #12, #13). | Medium | Handoff has actor-required semantic. |
| 7 | Migrate routes resume (#2). | Medium | Decision point: do we ALSO start stamping actor/timeout on resume? Behavior change vs. refactor. |
| 8 | Cleanup: `#[deprecated]` bare `build_controller_engine`, add CI lint preventing reintroduction. | Low | Closes the door. |

## Test coverage assessment

Sites with existing test coverage: scheduler (cron only, dispatch UNCOVERED), some workflow tests indirectly hit MCP triggers.

Sites with NO test coverage that are HIGH-risk to refactor: routes.rs resume, mcp/actor.rs handoff, advanced.rs continuation, all 4 GraphQL mutations.

**Recommendation:** PR 0 must include a mock-engine pattern (a thin trait + recorder) so each migration PR can assert the correct setter sequence is invoked. Without this, the refactor is a vibe.

## Open questions for product before PR 1

1. **`set_workflow_id` everywhere or only scheduler?** — implies a behavior change (analytics rollups now bucket per-workflow not per-execution).
2. **Should resume paths re-stamp actor/timeout?** — security-relevant; affects tier ceiling on resumed executions.
3. **Asymmetric effective_actor pattern** — bug or intent?

## Reference

Full reconnaissance report (with risk notes per site) generated by Plan subagent on 2026-04-28; preserved in conversation history at the same date.
