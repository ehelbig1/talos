//! Regression test for the fan-in early-ready dependency-counter bug.
//!
//! A `FanIn` node with an early-ready join mode (`Any`/`Majority`/`N`) is
//! enqueued as soon as ENOUGH parents finish — before every parent does. The
//! remaining parents then complete *after* the fan-in has already been
//! dispatched. Pre-fix, the per-child `pending` counter was decremented without
//! a `> 0` guard and was never removed once the join resolved, so each late
//! parent ran `*cnt -= 1` on `0`:
//!   * debug builds (overflow-checks on, as under `cargo test`) → panic, which
//!     aborts the whole workflow execution;
//!   * release builds → wrap to `usize::MAX`, which re-satisfied the early-ready
//!     check and RE-ENQUEUED the fan-in, double-dispatching its downstream
//!     subgraph.
//!
//! This test drives the real reactor with three async (module) parents feeding a
//! `JoinMode::Any` fan-in feeding a child module. Pre-fix it panics when the
//! second parent completes; post-fix the run succeeds and the child is
//! dispatched exactly once.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowGraphBuilder};
use talos_workflow_engine_core::{
    BoxError, ChainDispatchRequest, ChainDispatchResult, ChainStepResult, DispatchJob,
    DispatchResult, JoinMode, NodeDispatcher, StepStatus, SystemNodeKind, WasmModuleArtifact,
};
use talos_workflow_engine_test_utils::{memory::InMemoryModuleFetcher, minimal_engine};
use uuid::Uuid;

/// Records how many times each node id is dispatched, so the test can assert the
/// fan-in's child is dispatched exactly once (no double-dispatch).
#[derive(Default)]
struct CountingDispatcher {
    counts: Mutex<HashMap<Uuid, usize>>,
}

impl CountingDispatcher {
    fn count_for(&self, node_id: Uuid) -> usize {
        self.counts
            .lock()
            .unwrap()
            .get(&node_id)
            .copied()
            .unwrap_or(0)
    }
}

#[async_trait]
impl NodeDispatcher for CountingDispatcher {
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError> {
        *self.counts.lock().unwrap().entry(job.node_id).or_insert(0) += 1;
        Ok(DispatchResult {
            output: json!({"output": "ok"}),
        })
    }

    async fn dispatch_chain(
        &self,
        request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        for step in &request.steps {
            *self.counts.lock().unwrap().entry(step.node_id).or_insert(0) += 1;
        }
        let steps: Vec<ChainStepResult> = request
            .steps
            .iter()
            .map(|j| ChainStepResult {
                module_id: j.module_id,
                status: StepStatus::Success,
                output: json!({"output": "ok"}),
                error: None,
                execution_time_ms: 0,
            })
            .collect();
        Ok(ChainDispatchResult {
            steps,
            final_output: json!({"output": "ok"}),
            overall_status: StepStatus::Success,
        })
    }
}

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

fn engine_with_modules(ids: &[Uuid]) -> ParallelWorkflowEngine {
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    let mut fetcher = InMemoryModuleFetcher::new();
    for id in ids {
        fetcher = fetcher.with_module(*id, stub_artifact(*id));
    }
    engine.set_module_fetcher(Arc::new(fetcher));
    engine.set_execution_timeout(Some(Duration::from_secs(30)));
    engine
}

/// Three async parents → `JoinMode::Any` fan-in → child module.
#[tokio::test]
async fn fan_in_any_with_three_async_parents_dispatches_child_once() {
    let p1 = Uuid::new_v4();
    let p2 = Uuid::new_v4();
    let p3 = Uuid::new_v4();
    let child = Uuid::new_v4();

    let graph = WorkflowGraphBuilder::new()
        .add_module(p1.to_string(), p1, None)
        .add_module(p2.to_string(), p2, None)
        .add_module(p3.to_string(), p3, None)
        .add_system_node(
            "fan_in",
            SystemNodeKind::FanIn {
                join_mode: JoinMode::Any,
                aggregation_expr: None,
            },
        )
        .add_module(child.to_string(), child, None)
        .edge(p1.to_string(), "fan_in")
        .edge(p2.to_string(), "fan_in")
        .edge(p3.to_string(), "fan_in")
        .edge("fan_in", child.to_string())
        .build()
        .expect("graph builds");

    let mut engine = engine_with_modules(&[p1, p2, p3, child]);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load");

    let dispatcher = Arc::new(CountingDispatcher::default());
    let trigger = json!({ "event": "test" });

    // Pre-fix this panics (usize underflow under overflow-checks) when the
    // second/third parent completes after the fan-in was already enqueued.
    engine
        .run_with_trigger_input_transport(dispatcher.clone(), None, trigger, Uuid::new_v4())
        .await
        .expect("run succeeds — a panic here is the fan-in underflow regression");

    // The fan-in's downstream child must be dispatched EXACTLY once. Pre-fix the
    // release-build underflow re-enqueued the fan-in and double-dispatched it.
    assert_eq!(
        dispatcher.count_for(child),
        1,
        "fan-in child must be dispatched exactly once (no double-dispatch)"
    );
}
