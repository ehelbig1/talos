//! Sub-workflow recursion-depth guard.
//!
//! `AdapterSet::into_engine_with_graph` increments the dispatch
//! depth on every sub-workflow hydration and refuses to proceed when
//! the next depth would exceed the configured cap. The test below
//! constructs a workflow that transitively references itself via a
//! `SubWorkflow` node and confirms the engine bails with
//! `WorkflowEngineError::SubflowRecursionLimit` rather than
//! stack-overflowing.
//!
//! The non-recursive `into_engine` path doesn't enforce the check
//! (it's used by tests / pre-load scenarios where the caller is
//! responsible for not creating cycles); the test below also
//! confirms that `AdapterSet` correctly carries `current_subflow_depth`
//! across the boundary so a sub-engine can compute its own depth.

use std::sync::Arc;

use talos_workflow_engine::{
    AdapterSet, ParallelWorkflowEngine, WorkflowEngineError, WorkflowGraphBuilder,
    DEFAULT_MAX_SUBFLOW_DEPTH,
};
use talos_workflow_engine_core::{SystemNodeKind, WasmModuleArtifact, WorkflowGraphStore};
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher, memory::InMemoryModuleFetcher, minimal_engine,
};
use uuid::Uuid;

fn stub_artifact(id: Uuid) -> WasmModuleArtifact {
    WasmModuleArtifact {
        module_id: id,
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

#[test]
fn default_max_subflow_depth_is_documented_constant() {
    let engine = ParallelWorkflowEngine::new();
    assert_eq!(engine.max_subflow_depth(), DEFAULT_MAX_SUBFLOW_DEPTH);
    assert_eq!(DEFAULT_MAX_SUBFLOW_DEPTH, 16);
}

#[test]
fn current_depth_starts_at_zero_for_top_level() {
    let engine = ParallelWorkflowEngine::new();
    assert_eq!(engine.current_subflow_depth(), 0);
}

#[test]
fn into_engine_increments_depth() {
    // The non-graph path is unguarded by design — used by tests + by
    // pre-load helpers where the caller controls cycles. But it MUST
    // still increment the depth so a downstream `into_engine_with_graph`
    // sees the right baseline.
    let engine = ParallelWorkflowEngine::new();
    let sub = engine.adapter_set().into_engine();
    assert_eq!(sub.current_subflow_depth(), 1);
    let sub_sub = sub.adapter_set().into_engine();
    assert_eq!(sub_sub.current_subflow_depth(), 2);
}

#[test]
fn into_engine_with_graph_enforces_depth_check() {
    // Lower the cap to 2 so we can hit it in 3 hops.
    let mut engine = ParallelWorkflowEngine::new();
    engine.set_max_subflow_depth(2);

    let trivial_graph = WorkflowGraphBuilder::new()
        .add_module("only", Uuid::new_v4(), None)
        .build()
        .unwrap();

    // depth 0 → 1: OK (next_depth = 1 ≤ 2).
    let s1 = engine
        .adapter_set()
        .into_engine_with_graph(&trivial_graph)
        .expect("depth 1 within cap");
    assert_eq!(s1.current_subflow_depth(), 1);

    // depth 1 → 2: OK (next_depth = 2 ≤ 2).
    let s2 = s1
        .adapter_set()
        .into_engine_with_graph(&trivial_graph)
        .expect("depth 2 within cap");
    assert_eq!(s2.current_subflow_depth(), 2);

    // depth 2 → 3: REJECT. The next dispatch would land at depth 3,
    // exceeding the cap of 2. The error names the depth + limit so
    // operators can immediately tell what to raise.
    //
    // `ParallelWorkflowEngine` doesn't impl `Debug` (the Arc<dyn>
    // adapters can't reasonably stringify), so the manual match is
    // load-bearing — `expect_err` would require it.
    let result = s2.adapter_set().into_engine_with_graph(&trivial_graph);
    let err = match result {
        Ok(_) => panic!("depth 3 must exceed cap"),
        Err(e) => e,
    };
    match err {
        WorkflowEngineError::SubflowRecursionLimit { depth, limit } => {
            assert_eq!(depth, 3);
            assert_eq!(limit, 2);
        }
        other => panic!("expected SubflowRecursionLimit, got: {other:?}"),
    }
}

#[test]
fn max_subflow_depth_propagates_through_adapter_set() {
    // Per the AGENTS.md "miss any one step and sub-workflow dispatch
    // silently drops the adapter" rule. Without this, a parent
    // setting `max_subflow_depth = 3` would silently revert to 16
    // inside any sub-workflow loop.
    let mut engine = ParallelWorkflowEngine::new();
    engine.set_max_subflow_depth(3);
    let cloned = engine.adapter_set().into_engine();
    assert_eq!(cloned.max_subflow_depth(), 3);
}

#[tokio::test]
async fn self_referential_subworkflow_terminates_with_recursion_error() {
    // End-to-end: a workflow whose sole node is a `SubWorkflow`
    // pointing at itself. Without the depth guard this would
    // stack-overflow the reactor. With it, the run terminates
    // promptly with the error envelope sub-workflow handlers wrap
    // around `SubflowError::BuildFailed`.
    //
    // Lower the cap to 4 so the test runs fast — at 16 the SubflowError
    // chain would still be cheap, but 4 makes the failure obvious in
    // a test trace.

    let sub_wf_id = Uuid::new_v4();

    // The graph IS the sub-workflow it dispatches — every level of
    // recursion sees the same graph, so the cycle is structural.
    let recursive_graph = WorkflowGraphBuilder::new()
        .add_system_node(
            "self",
            SystemNodeKind::SubWorkflow {
                workflow_id: sub_wf_id,
                timeout_secs: 30,
            },
        )
        .build()
        .unwrap();

    // Tiny in-memory graph store that returns the same graph for any
    // workflow_id — the engine's batch prefetch will load it.
    struct OneGraphStore(serde_json::Value);
    use async_trait::async_trait;
    use std::collections::HashMap;
    #[async_trait]
    impl WorkflowGraphStore for OneGraphStore {
        async fn get_graph(
            &self,
            _id: Uuid,
            _user: Uuid,
        ) -> Result<Option<serde_json::Value>, talos_workflow_engine_core::BoxError> {
            Ok(Some(self.0.clone()))
        }
        async fn get_graphs(
            &self,
            ids: &[Uuid],
            _user: Uuid,
        ) -> Result<HashMap<Uuid, serde_json::Value>, talos_workflow_engine_core::BoxError>
        {
            Ok(ids.iter().map(|&id| (id, self.0.clone())).collect())
        }
    }

    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(InMemoryModuleFetcher::new()));
    engine.set_graph_store(Arc::new(OneGraphStore(recursive_graph.clone())));
    engine.set_max_subflow_depth(4);
    engine
        .load_graph_from_json(&serde_json::to_string(&recursive_graph).unwrap())
        .await
        .expect("load");

    let dispatcher = Arc::new(ScriptedDispatcher::new());
    let started = std::time::Instant::now();
    let ctx = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect("workflow returns ok with error envelope, not Err");
    let elapsed = started.elapsed();

    // The sub-workflow handler converts the recursion error into an
    // error envelope (`__error: true`). The exact message differs by
    // handler; what matters is the workflow terminated quickly
    // instead of stack-overflowing.
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "self-referential workflow should terminate promptly, took {elapsed:?}"
    );
    let envelope = ctx.results.values().next().expect("has a result");
    assert_eq!(
        envelope.get("__error").and_then(|v| v.as_bool()),
        Some(true)
    );
    let msg = envelope
        .get("error_message")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        msg.contains("recursion") || msg.contains("depth") || msg.contains("Sub-workflow"),
        "expected a recursion-related error message, got: {msg}"
    );
}

// Suppress unused-import warning in CI if any helper is reorganized.
#[allow(dead_code)]
fn _suppress_unused() -> AdapterSet {
    ParallelWorkflowEngine::new().adapter_set()
}

// Likewise — this test pulls in the full engine surface for setup
// helpers; the artifact stub lives at file scope so multiple tests
// could share it if the file grows.
#[allow(dead_code)]
fn _stub_artifact_unused_in_some_builds(id: Uuid) -> WasmModuleArtifact {
    stub_artifact(id)
}
