//! Workflow-level timeout enforcement.
//!
//! `ParallelWorkflowEngine::execution_timeout_secs` is documented as
//! the "maximum execution time for the entire workflow." Before the
//! scheduler unification the fresh-run path (`run_with_transport`)
//! silently ignored the field — a runaway workflow could hold
//! resources indefinitely even with the timeout set. These tests
//! lock in that the field is now enforced on both entry points:
//!
//! * [`run_with_transport`](talos_workflow_engine::ParallelWorkflowEngine::run_with_transport)
//!   — the fresh path.
//! * [`run_with_seed_with_transport`](talos_workflow_engine::ParallelWorkflowEngine::run_with_seed_with_transport)
//!   — the seeded-resume path (always enforced historically).
//! * `execution_timeout_secs = 0` opts out: the scheduler runs
//!   without a wall-clock cap so only per-node timeouts apply. This
//!   lane is tested separately so the "explicit opt-out" contract
//!   stays stable.
//!
//! The tests use a dispatcher that parks for 10 seconds before
//! returning. With `execution_timeout_secs = 1` the reactor is
//! wrapped in a 1-second `tokio::time::timeout` that trips first;
//! with `execution_timeout_secs = 0` the dispatcher's output is
//! observed, confirming the timeout is disabled rather than
//! applied-to-zero.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowEngineError, WorkflowGraphBuilder};
use talos_workflow_engine_core::{
    BoxError, ChainDispatchRequest, ChainDispatchResult, ChainStepResult, DispatchJob,
    DispatchResult, NodeDispatcher, StepStatus, WasmModuleArtifact,
};
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher, memory::InMemoryModuleFetcher, minimal_engine,
};
use uuid::Uuid;

/// Dispatcher that parks `dispatch` for `delay` before returning a
/// canned success. Lets a workflow-level timeout trip first, without
/// the dispatcher ever observing the cancellation.
struct SleepingDispatcher {
    delay: Duration,
}

#[async_trait]
impl NodeDispatcher for SleepingDispatcher {
    async fn dispatch(&self, _job: DispatchJob) -> Result<DispatchResult, BoxError> {
        tokio::time::sleep(self.delay).await;
        Ok(DispatchResult {
            output: json!({"output": "slow"}),
        })
    }

    async fn dispatch_chain(
        &self,
        request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        tokio::time::sleep(self.delay).await;
        let steps: Vec<ChainStepResult> = request
            .steps
            .iter()
            .map(|j| ChainStepResult {
                module_id: j.module_id,
                status: StepStatus::Success,
                output: json!({"output": "slow"}),
                error: None,
                execution_time_ms: 0,
            })
            .collect();
        Ok(ChainDispatchResult {
            steps,
            final_output: json!({"output": "slow"}),
            overall_status: StepStatus::Success,
        })
    }
}

fn stub_artifact(module_id: Uuid) -> WasmModuleArtifact {
    WasmModuleArtifact {
        module_id,
        content_hash: "stub".into(),
        wasm_bytes: vec![],
        oci_url: None,
        max_fuel: 1_000_000,
        capability_world: "stub".into(),
        allowed_hosts: vec![],
        allowed_methods: vec![],
        allowed_secrets: vec![],
        requires_approval_for: vec![],
        integration_name: None,
        config: None,
    }
}

/// A three-node fan-out graph ("root" → [a, b]) so the scheduler does
/// real dispatch work on the *single-node* path. A two-node `a → b`
/// linear graph would trigger the pipeline-chain optimisation
/// (`detect_linear_chains`), whose wire format sets
/// `DispatchJob.module_id = node_id` rather than the resolved template
/// UUID — `ScriptedDispatcher` keys responses by `module_id` and
/// wouldn't find them. Fan-out keeps every node on the per-node
/// dispatch path.
fn build_slow_graph() -> (serde_json::Value, Uuid, Uuid, Uuid) {
    let root_mod = Uuid::new_v4();
    let a_mod = Uuid::new_v4();
    let b_mod = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module("root", root_mod, None)
        .add_module("a", a_mod, None)
        .add_module("b", b_mod, None)
        .edge("root", "a")
        .edge("root", "b")
        .build()
        .expect("builder inputs well-formed");
    (graph, root_mod, a_mod, b_mod)
}

fn engine_with_timeout(
    secs: u64,
    root_mod: Uuid,
    a_mod: Uuid,
    b_mod: Uuid,
) -> ParallelWorkflowEngine {
    let mut engine = minimal_engine();
    let fetcher = Arc::new(
        InMemoryModuleFetcher::new()
            .with_module(root_mod, stub_artifact(root_mod))
            .with_module(a_mod, stub_artifact(a_mod))
            .with_module(b_mod, stub_artifact(b_mod)),
    );
    engine.set_module_fetcher(fetcher);
    engine.set_user_id(Uuid::new_v4());
    engine.set_execution_timeout_secs(secs);
    engine
}

#[tokio::test]
async fn run_with_transport_enforces_workflow_timeout() {
    // Regression test for the scheduler-unification commit: the fresh
    // path previously ignored execution_timeout_secs entirely. This
    // test fails on a pre-unification engine because the workflow
    // would wait for the dispatcher's 10-second sleep to finish
    // (and then another 10s for the downstream node).
    let (graph_json, root_mod, a_mod, b_mod) = build_slow_graph();
    let mut engine = engine_with_timeout(1, root_mod, a_mod, b_mod);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("graph loads");

    let dispatcher = Arc::new(SleepingDispatcher {
        delay: Duration::from_secs(10),
    });
    let started = std::time::Instant::now();
    let err = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect_err("workflow must time out");
    let elapsed = started.elapsed();

    // The timeout failure mode is a typed `WorkflowEngineError::Timeout`
    // variant — pattern-match it so we catch a regression to the
    // catch-all `Execution(String)` form rather than only relying on
    // a substring match.
    assert!(
        matches!(err, WorkflowEngineError::Timeout { secs: 1 }),
        "expected Timeout {{ secs: 1 }}, got: {err:?}"
    );
    // Elapsed should be close to the 1-second cap — give generous
    // slack for CI scheduling but fail if it took as long as the
    // dispatcher's natural sleep.
    assert!(
        elapsed < Duration::from_secs(5),
        "timeout took {elapsed:?}, expected ~1s"
    );
}

#[tokio::test]
async fn run_with_seed_with_transport_enforces_workflow_timeout() {
    // Complement to the fresh-path test: the seeded path has always
    // enforced the timeout; this test locks that behaviour in post-
    // unification.
    let (graph_json, root_mod, a_mod, b_mod) = build_slow_graph();
    let mut engine = engine_with_timeout(1, root_mod, a_mod, b_mod);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("graph loads");

    let dispatcher = Arc::new(SleepingDispatcher {
        delay: Duration::from_secs(10),
    });
    let started = std::time::Instant::now();
    // Seed with an empty map — we want the dispatcher to actually run
    // and sleep so the scheduler's timer is what bounds the wait.
    let err = engine
        .run_with_seed_with_transport(
            dispatcher,
            None,
            std::collections::HashMap::new(),
            Uuid::new_v4(),
        )
        .await
        .expect_err("workflow must time out");
    let elapsed = started.elapsed();
    assert!(
        matches!(err, WorkflowEngineError::Timeout { secs: 1 }),
        "expected Timeout {{ secs: 1 }}, got: {err:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "timeout took {elapsed:?}, expected ~1s"
    );
}

#[tokio::test]
async fn typed_execution_timeout_round_trips() {
    // The Option<Duration> setter is the preferred form for new code.
    // Verify both sides of the API agree on the disabled / enabled
    // distinction so callers can mix them without surprises.
    let mut engine = ParallelWorkflowEngine::new();

    engine.set_execution_timeout(None);
    assert_eq!(engine.execution_timeout(), None);
    assert_eq!(engine.execution_timeout_secs(), 0);

    engine.set_execution_timeout(Some(Duration::from_secs(120)));
    assert_eq!(engine.execution_timeout(), Some(Duration::from_secs(120)));
    assert_eq!(engine.execution_timeout_secs(), 120);

    // Bridging through the legacy setter still produces a coherent
    // typed read — `0` is the documented disable sentinel.
    engine.set_execution_timeout_secs(0);
    assert_eq!(engine.execution_timeout(), None);

    engine.set_execution_timeout_secs(45);
    assert_eq!(engine.execution_timeout(), Some(Duration::from_secs(45)));
}

#[tokio::test]
async fn execution_timeout_secs_zero_disables_the_cap() {
    // Opt-out lane: setting the field to 0 should let the workflow
    // run to completion (bounded by per-node timeouts only). We use
    // a ScriptedDispatcher returning immediately so the test finishes
    // in milliseconds even with no workflow-level cap.
    let (graph_json, root_mod, a_mod, b_mod) = build_slow_graph();
    let mut engine = engine_with_timeout(0, root_mod, a_mod, b_mod);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("graph loads");

    let dispatcher = Arc::new(
        ScriptedDispatcher::new()
            .with_response(root_mod, json!({"output": "root"}))
            .with_response(a_mod, json!({"output": "a"}))
            .with_response(b_mod, json!({"output": "b"})),
    );
    let ctx = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect("no timeout when execution_timeout_secs = 0");
    assert_eq!(ctx.results.len(), 3, "all three nodes should complete");
}

#[tokio::test]
async fn node_timings_populated_on_fresh_runs() {
    // Post-unification property: WorkflowContext.node_timings used to
    // be empty on the fresh path and populated on the seeded path.
    // Both now populate it. Lock in the fresh-path side.
    let (graph_json, root_mod, a_mod, b_mod) = build_slow_graph();
    let mut engine = engine_with_timeout(30, root_mod, a_mod, b_mod);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("graph loads");

    let dispatcher = Arc::new(
        ScriptedDispatcher::new()
            .with_response(root_mod, json!({"output": "root"}))
            .with_response(a_mod, json!({"output": "a"}))
            .with_response(b_mod, json!({"output": "b"})),
    );
    let ctx = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect("workflow completes");

    // Every dispatched node should appear in node_timings. The fan-out
    // keeps all three on the single-node path (no chain consolidation).
    assert!(
        !ctx.node_timings.is_empty(),
        "node_timings should be populated on fresh runs"
    );
    assert_eq!(
        ctx.node_timings.len(),
        3,
        "all three nodes should have a timing entry"
    );
}
