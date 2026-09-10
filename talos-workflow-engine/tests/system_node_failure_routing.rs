//! A node the engine records as FAILED must decide the run's fate.
//!
//! Two system-node kinds used to commit their own `{__error: …}`
//! envelope as an ordinary successful node result:
//!
//! * `SubWorkflow` — `try_dispatch_sub_workflow` wrote a `node_failed`
//!   event itself whenever the collapsed child output reported an error,
//!   and then handed that same envelope back to the reactor, which
//!   committed it via `commit_result!`. The run finished `completed`
//!   with `workflow_executions.error_message` NULL, beside a
//!   `node_failed` row naming one of its own nodes — a record
//!   contradicting itself in three places at once. Every sub-workflow
//!   failure took this path, not just an exotic one: a missing child
//!   graph, a child whose module failed, a recursion-depth refusal and a
//!   child emitting a bare `{"__error": "…"}` string all collapse to the
//!   same envelope.
//! * `AgentLoop` / `ReActLoop` — same commit path, and it emitted no
//!   event at all, so a loop pointed at a deleted body workflow ran zero
//!   iterations and reported a clean run with nothing to look at.
//!
//! Both now route through `route_system_node_output`, the reactor's ONE
//! system-node failure path (judge / ensemble / verify / digest nodes
//! have used it all along). The tests below drive the real
//! `run_with_transport` reactor and assert the four outcomes that path
//! owns: the run fails; `__continue_on_error` still survives it; an
//! error edge still catches it; and exactly ONE `node_failed` event is
//! written for the node — the double-emit that a naive "route it AND
//! keep the old emitter" fix would produce.
//!
//! These are call-site tests on purpose. The routing helper's own unit
//! tests cannot see a reactor branch that never calls it, which is the
//! shape of the defect they exist to prevent.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowGraphBuilder};
use talos_workflow_engine_core::{
    BoxError, ChainDispatchRequest, ChainDispatchResult, ChainStepResult, DispatchJob,
    DispatchResult, NodeDispatcher, StepStatus, SystemNodeKind, WasmModuleArtifact,
    WorkflowGraphStore,
};
use talos_workflow_engine_test_utils::{
    capture::CaptureEventSink, memory::InMemoryModuleFetcher, minimal_engine,
};
use uuid::Uuid;

// ── Harness ─────────────────────────────────────────────────────────

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

/// Returns one fixed output for every module dispatch. The child
/// workflow's only node uses it, so the test controls exactly what the
/// child collapses to.
struct FixedOutputDispatcher(serde_json::Value);

#[async_trait]
impl NodeDispatcher for FixedOutputDispatcher {
    async fn dispatch(&self, _job: DispatchJob) -> Result<DispatchResult, BoxError> {
        Ok(DispatchResult {
            output: self.0.clone(),
        })
    }

    async fn dispatch_chain(
        &self,
        request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        let steps: Vec<ChainStepResult> = request
            .steps
            .iter()
            .map(|j| ChainStepResult {
                module_id: j.module_id,
                status: StepStatus::Success,
                output: self.0.clone(),
                error: None,
                execution_time_ms: 0,
            })
            .collect();
        Ok(ChainDispatchResult {
            steps,
            final_output: self.0.clone(),
            overall_status: StepStatus::Success,
        })
    }
}

/// Serves one graph for every requested workflow id, or nothing at all.
struct OneGraphStore(Option<serde_json::Value>);

#[async_trait]
impl WorkflowGraphStore for OneGraphStore {
    async fn get_graph(
        &self,
        _id: Uuid,
        _user: Uuid,
    ) -> Result<talos_workflow_engine_core::GraphLookup, BoxError> {
        Ok(self.0.clone().map_or(
            talos_workflow_engine_core::GraphLookup::Absent,
            talos_workflow_engine_core::GraphLookup::Found,
        ))
    }
    async fn get_graphs(
        &self,
        ids: &[Uuid],
        _user: Uuid,
    ) -> Result<HashMap<Uuid, serde_json::Value>, BoxError> {
        Ok(match &self.0 {
            Some(g) => ids.iter().map(|&id| (id, g.clone())).collect(),
            None => HashMap::new(),
        })
    }
}

/// The child workflow: a single module node. The dispatcher decides
/// what it returns, so the same graph serves the failing and the
/// succeeding case.
fn child_graph(module_id: Uuid) -> serde_json::Value {
    WorkflowGraphBuilder::new()
        .add_module(module_id.to_string(), module_id, None)
        .build()
        .expect("child graph builds")
}

fn engine_for(
    parent_graph: &serde_json::Value,
    child: Option<serde_json::Value>,
    module_id: Uuid,
    events: Option<Arc<CaptureEventSink>>,
) -> ParallelWorkflowEngine {
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new().with_module(module_id, stub_artifact(module_id)),
    ));
    engine.set_graph_store(Arc::new(OneGraphStore(child)));
    engine.set_execution_timeout(Some(Duration::from_secs(30)));
    if let Some(sink) = events {
        engine.set_event_sink(sink);
    }
    futures::executor::block_on(
        engine.load_graph_from_json(&serde_json::to_string(parent_graph).unwrap()),
    )
    .expect("parent graph loads");
    engine
}

/// The observed shape: a child whose module output carries a bare
/// STRING under `__error`. #733 made that classify as a failure; this
/// file is about what the engine then does with the classification.
fn string_error_output() -> serde_json::Value {
    json!({ "__error": "child blew up" })
}

// ── SubWorkflow ─────────────────────────────────────────────────────

#[tokio::test]
async fn subworkflow_child_error_fails_the_parent_run() {
    let sub_wf_id = Uuid::new_v4();
    let module_id = Uuid::new_v4();
    let parent = WorkflowGraphBuilder::new()
        .add_system_node(
            "call_child",
            SystemNodeKind::SubWorkflow {
                workflow_id: sub_wf_id,
                timeout_secs: 30,
            },
        )
        .build()
        .expect("parent graph builds");

    let engine = engine_for(&parent, Some(child_graph(module_id)), module_id, None);
    let result = engine
        .run_with_transport(
            Arc::new(FixedOutputDispatcher(string_error_output())),
            None,
            Uuid::new_v4(),
        )
        .await;

    let err = match result {
        Ok(_) => panic!(
            "a sub-workflow that reported an error must fail the parent run; \
             committing its envelope as a successful node result is what produced \
             `completed` + `node_failed` + `error_message: NULL`"
        ),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("child blew up"),
        "the run's error must name the child's reason, got: {err}"
    );
}

#[tokio::test]
async fn subworkflow_missing_child_graph_fails_the_parent_run() {
    // The other, commoner shape: the child workflow cannot be loaded at
    // all. `dispatch_subworkflow` turns the `SubflowError` into the same
    // envelope, so it took the same silent-success path.
    let sub_wf_id = Uuid::new_v4();
    let module_id = Uuid::new_v4();
    let parent = WorkflowGraphBuilder::new()
        .add_system_node(
            "call_child",
            SystemNodeKind::SubWorkflow {
                workflow_id: sub_wf_id,
                timeout_secs: 30,
            },
        )
        .build()
        .expect("parent graph builds");

    let engine = engine_for(&parent, None, module_id, None);
    let result = engine
        .run_with_transport(
            Arc::new(FixedOutputDispatcher(json!({ "ok": true }))),
            None,
            Uuid::new_v4(),
        )
        .await;
    assert!(
        result.is_err(),
        "an unloadable sub-workflow must fail the parent run"
    );
}

#[tokio::test]
async fn subworkflow_child_error_is_survivable_with_continue_on_error() {
    // `__continue_on_error` is the author's declaration that this
    // failure is handled. Routing through the reactor's failure path is
    // what makes the declaration reachable at all — the old commit path
    // never consulted it.
    let sub_wf_id = Uuid::new_v4();
    let module_id = Uuid::new_v4();
    let parent = WorkflowGraphBuilder::new()
        .add_system_node(
            "call_child",
            SystemNodeKind::SubWorkflow {
                workflow_id: sub_wf_id,
                timeout_secs: 30,
            },
        )
        .with_continue_on_error("call_child")
        .build()
        .expect("parent graph builds");

    let engine = engine_for(&parent, Some(child_graph(module_id)), module_id, None);
    let ctx = engine
        .run_with_transport(
            Arc::new(FixedOutputDispatcher(string_error_output())),
            None,
            Uuid::new_v4(),
        )
        .await
        .expect("continue_on_error keeps the run alive");

    let envelope = ctx
        .results
        .values()
        .find(|v| v.get("__continued").is_some())
        .expect("the failed node's `__continued` envelope is in the results");
    assert_eq!(
        envelope.get("__error").and_then(|v| v.as_bool()),
        Some(true)
    );
}

#[tokio::test]
async fn subworkflow_child_error_routes_to_an_error_edge() {
    let sub_wf_id = Uuid::new_v4();
    let module_id = Uuid::new_v4();
    let handler_module = Uuid::new_v4();
    let parent = WorkflowGraphBuilder::new()
        .add_system_node(
            "call_child",
            SystemNodeKind::SubWorkflow {
                workflow_id: sub_wf_id,
                timeout_secs: 30,
            },
        )
        .add_module("handler", handler_module, None)
        .add_raw_edge(json!({
            "source": "call_child",
            "target": "handler",
            "sourceHandle": "output",
            "targetHandle": "input",
            "edge_type": "error",
        }))
        .build()
        .expect("parent graph builds");

    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new()
            .with_module(module_id, stub_artifact(module_id))
            .with_module(handler_module, stub_artifact(handler_module)),
    ));
    engine.set_graph_store(Arc::new(OneGraphStore(Some(child_graph(module_id)))));
    engine.set_execution_timeout(Some(Duration::from_secs(30)));
    engine
        .load_graph_from_json(&serde_json::to_string(&parent).unwrap())
        .await
        .expect("parent graph loads");

    let ctx = engine
        .run_with_transport(
            Arc::new(FixedOutputDispatcher(string_error_output())),
            None,
            Uuid::new_v4(),
        )
        .await
        .expect("an error edge off the sub-workflow node must catch the failure");

    // `is_ok()` alone would NOT distinguish the fix from the defect —
    // committing the envelope as a success also produces an `Ok` run.
    // (Measured: the first version of this test passed against the
    // reverted call site.) What separates them is which child ran. On
    // SUCCESS the engine writes `{"__skipped": true}` into every
    // error-edge child; on FAILURE it routes to them. So the handler's
    // own result is the discriminator.
    let handler_id = engine
        .node_labels()
        .iter()
        .find(|(_, label)| label.as_str() == "handler")
        .map(|(id, _)| *id)
        .expect("handler node is in the graph");
    let handler_result = ctx
        .results
        .get(&handler_id)
        .expect("handler node has a result");
    assert!(
        handler_result.get("__skipped").is_none(),
        "the error handler must RUN, not be skipped as a dead success-path \
         child; got: {handler_result}"
    );

    // …and the failed node's own slot carries the error payload the
    // failure path writes for its handlers, naming the node.
    let failed = ctx
        .results
        .values()
        .find(|v| v.get("failed_node").is_some())
        .expect("the failed node's error payload is in the results");
    assert_eq!(failed.get("__error").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        failed.get("failed_node").and_then(|v| v.as_str()),
        Some("call_child")
    );
}

#[tokio::test]
async fn subworkflow_failure_writes_exactly_one_node_failed_event() {
    // The handler used to write `node_failed` itself. Routing the same
    // envelope through the reactor without removing that emitter would
    // put TWO `node_failed` rows on one node — a trace that double-counts
    // is its own misleading record.
    let sub_wf_id = Uuid::new_v4();
    let module_id = Uuid::new_v4();
    let parent = WorkflowGraphBuilder::new()
        .add_system_node(
            "call_child",
            SystemNodeKind::SubWorkflow {
                workflow_id: sub_wf_id,
                timeout_secs: 30,
            },
        )
        .build()
        .expect("parent graph builds");

    let events = Arc::new(CaptureEventSink::new());
    let engine = engine_for(
        &parent,
        Some(child_graph(module_id)),
        module_id,
        Some(events.clone()),
    );
    let result = engine
        .run_with_transport(
            Arc::new(FixedOutputDispatcher(string_error_output())),
            None,
            Uuid::new_v4(),
        )
        .await;
    assert!(result.is_err(), "the run must fail");

    let failed = events.events_of_type("node_failed");
    assert_eq!(
        failed.len(),
        1,
        "exactly one node_failed event per failed sub-workflow node, got {}: {:?}",
        failed.len(),
        failed.iter().map(|e| &e.log_message).collect::<Vec<_>>()
    );
    assert!(
        events.events_of_type("node_completed").is_empty(),
        "a failed sub-workflow must not also report node_completed"
    );
}

#[tokio::test]
async fn subworkflow_success_still_reports_node_completed() {
    // The success half is untouched: the handler still writes its own
    // `node_completed` with the measured duration.
    let sub_wf_id = Uuid::new_v4();
    let module_id = Uuid::new_v4();
    let parent = WorkflowGraphBuilder::new()
        .add_system_node(
            "call_child",
            SystemNodeKind::SubWorkflow {
                workflow_id: sub_wf_id,
                timeout_secs: 30,
            },
        )
        .build()
        .expect("parent graph builds");

    let events = Arc::new(CaptureEventSink::new());
    let engine = engine_for(
        &parent,
        Some(child_graph(module_id)),
        module_id,
        Some(events.clone()),
    );
    engine
        .run_with_transport(
            Arc::new(FixedOutputDispatcher(json!({ "value": 7 }))),
            None,
            Uuid::new_v4(),
        )
        .await
        .expect("a clean child keeps the parent run clean");

    assert_eq!(
        events.events_of_type("node_completed").len(),
        1,
        "the successful sub-workflow dispatch still writes node_completed"
    );
    assert!(events.events_of_type("node_failed").is_empty());
}

// ── AgentLoop / ReActLoop ───────────────────────────────────────────

#[cfg(feature = "llm-primitives")]
#[tokio::test]
async fn agent_loop_missing_body_workflow_fails_the_run() {
    let body_wf_id = Uuid::new_v4();
    let module_id = Uuid::new_v4();
    let parent = WorkflowGraphBuilder::new()
        .add_system_node(
            "agent",
            SystemNodeKind::AgentLoop {
                body_workflow_id: body_wf_id,
                max_iterations: 2,
                inject_history: false,
                timeout_secs: 30,
            },
        )
        .build()
        .expect("parent graph builds");

    let engine = engine_for(&parent, None, module_id, None);
    let result = engine
        .run_with_transport(
            Arc::new(FixedOutputDispatcher(json!({ "ok": true }))),
            None,
            Uuid::new_v4(),
        )
        .await;
    assert!(
        result.is_err(),
        "an AgentLoop whose body workflow cannot be loaded must fail the run, \
         not report a clean zero-iteration success"
    );
}

#[cfg(feature = "llm-primitives")]
#[tokio::test]
async fn react_loop_missing_body_workflow_fails_the_run() {
    // ReActLoop shares `try_dispatch_agent_loop`, so it shares the fix —
    // asserted rather than assumed, because a future split of the two
    // dispatchers is exactly how one of them would regress alone.
    let body_wf_id = Uuid::new_v4();
    let module_id = Uuid::new_v4();
    let parent = WorkflowGraphBuilder::new()
        .add_system_node(
            "react",
            SystemNodeKind::ReActLoop {
                body_workflow_id: body_wf_id,
                max_iterations: 2,
                inject_history: false,
                timeout_secs: 30,
            },
        )
        .build()
        .expect("parent graph builds");

    let engine = engine_for(&parent, None, module_id, None);
    let result = engine
        .run_with_transport(
            Arc::new(FixedOutputDispatcher(json!({ "ok": true }))),
            None,
            Uuid::new_v4(),
        )
        .await;
    assert!(result.is_err(), "ReActLoop shares the AgentLoop dispatcher");
}

#[cfg(feature = "llm-primitives")]
#[tokio::test]
async fn agent_loop_failure_is_survivable_with_continue_on_error() {
    let body_wf_id = Uuid::new_v4();
    let module_id = Uuid::new_v4();
    let parent = WorkflowGraphBuilder::new()
        .add_system_node(
            "agent",
            SystemNodeKind::AgentLoop {
                body_workflow_id: body_wf_id,
                max_iterations: 2,
                inject_history: false,
                timeout_secs: 30,
            },
        )
        .with_continue_on_error("agent")
        .build()
        .expect("parent graph builds");

    let engine = engine_for(&parent, None, module_id, None);
    let ctx = engine
        .run_with_transport(
            Arc::new(FixedOutputDispatcher(json!({ "ok": true }))),
            None,
            Uuid::new_v4(),
        )
        .await
        .expect("continue_on_error keeps the run alive");

    // `Ok` alone would NOT distinguish the fix from the defect — the old
    // commit path also produced an `Ok` run. (Measured: this test passed
    // against the reverted call site until this assertion was added.)
    // `__continued` is written ONLY by the failure path's
    // `continue_on_error` branch, so its presence is the discriminator.
    let envelope = ctx
        .results
        .values()
        .find(|v| v.get("__continued").is_some())
        .expect("the failure path's `__continued` envelope is in the results");
    assert_eq!(
        envelope.get("__error").and_then(|v| v.as_bool()),
        Some(true)
    );
}

// ── Child-dispatch timeout (2026-09-10) ──────────────────────────────────────
//
// `timeout_secs` on every child-running kind was parsed and never applied
// (destructured `timeout_secs: _` at seven dispatch sites). It is applied now,
// OPT-IN via `enforce_timeout: true`, because the `add_sub_workflow_node`
// tool stamps `timeout_secs: 30` on every node it authors and the fleet's
// LLM-bearing children legitimately run past 30 s. The typed builder emits
// the marker for a non-zero timeout; a raw node without it is bounded by the
// run's remaining budget only. On expiry the NODE fails through the reactor's
// one system-node failure path — the same route the tests above pin.

/// Sleeps, then answers. The child workflow's only node uses it, so the
/// test controls exactly how long the child takes.
struct SleepingDispatcher(Duration, serde_json::Value);

#[async_trait]
impl NodeDispatcher for SleepingDispatcher {
    async fn dispatch(&self, _job: DispatchJob) -> Result<DispatchResult, BoxError> {
        tokio::time::sleep(self.0).await;
        Ok(DispatchResult {
            output: self.1.clone(),
        })
    }

    async fn dispatch_chain(
        &self,
        request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        tokio::time::sleep(self.0).await;
        let steps: Vec<ChainStepResult> = request
            .steps
            .iter()
            .map(|j| ChainStepResult {
                module_id: j.module_id,
                status: StepStatus::Success,
                output: self.1.clone(),
                error: None,
                execution_time_ms: 0,
            })
            .collect();
        Ok(ChainDispatchResult {
            steps,
            final_output: self.1.clone(),
            overall_status: StepStatus::Success,
        })
    }
}

/// A child that sleeps past an EXPLICIT (typed-builder) `timeout_secs` fails
/// the node, the run's error names the kind and the cap, and it does so well
/// before the 30 s run budget — i.e. the per-node cap, not the outer timeout,
/// decided it.
#[tokio::test]
async fn subworkflow_child_past_an_explicit_timeout_fails_the_node() {
    let sub_wf_id = Uuid::new_v4();
    let module_id = Uuid::new_v4();
    let parent = WorkflowGraphBuilder::new()
        .add_system_node(
            "call_child",
            SystemNodeKind::SubWorkflow {
                workflow_id: sub_wf_id,
                timeout_secs: 1,
            },
        )
        .build()
        .expect("parent graph builds");
    assert_eq!(
        parent["nodes"][0]["data"]["enforce_timeout"],
        json!(true),
        "a typed non-zero timeout is an author's choice and must opt in"
    );

    let engine = engine_for(&parent, Some(child_graph(module_id)), module_id, None);
    let started = std::time::Instant::now();
    let result = engine
        .run_with_transport(
            Arc::new(SleepingDispatcher(
                Duration::from_secs(4),
                json!({ "ok": true }),
            )),
            None,
            Uuid::new_v4(),
        )
        .await;
    let elapsed = started.elapsed();

    let err = match result {
        Ok(_) => panic!("a child that outlives its enforced timeout must fail the run"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("sub_workflow timed out after 1s"),
        "the run's error must name the kind and the cap, got: {err}"
    );
    assert!(
        err.contains("node timeout_secs"),
        "the message must say the NODE cap decided it, got: {err}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "the node cap (1 s), not the child's 4 s sleep or the 30 s run budget, must end it; took {elapsed:?}"
    );
}

/// The control: a child that finishes under its explicit timeout succeeds
/// and the run completes.
#[tokio::test]
async fn subworkflow_child_under_an_explicit_timeout_succeeds() {
    let sub_wf_id = Uuid::new_v4();
    let module_id = Uuid::new_v4();
    let parent = WorkflowGraphBuilder::new()
        .add_system_node(
            "call_child",
            SystemNodeKind::SubWorkflow {
                workflow_id: sub_wf_id,
                timeout_secs: 5,
            },
        )
        .build()
        .expect("parent graph builds");

    let engine = engine_for(&parent, Some(child_graph(module_id)), module_id, None);
    let result = engine
        .run_with_transport(
            Arc::new(SleepingDispatcher(
                Duration::from_millis(200),
                json!({ "ok": true }),
            )),
            None,
            Uuid::new_v4(),
        )
        .await;
    assert!(
        result.is_ok(),
        "a child under its timeout must not be failed: {:?}",
        result.err()
    );
}

/// The MCP-stamped shape: `timeout_secs: 1` with NO `enforce_timeout` marker
/// — exactly what `add_sub_workflow_node` writes for every node with its
/// default of 30. It must NOT be enforced; the child runs past it and the run
/// completes (bounded only by the 30 s run budget the harness sets).
#[tokio::test]
async fn subworkflow_stored_timeout_without_the_marker_is_not_enforced() {
    let sub_wf_id = Uuid::new_v4();
    let module_id = Uuid::new_v4();
    let parent = WorkflowGraphBuilder::new()
        .add_raw_node(json!({
            "id": "call_child",
            "type": "system:sub_workflow",
            "kind": "sub_workflow",
            "data": { "sub_workflow_id": sub_wf_id.to_string(), "timeout_secs": 1 }
        }))
        .build()
        .expect("parent graph builds");

    let engine = engine_for(&parent, Some(child_graph(module_id)), module_id, None);
    let result = engine
        .run_with_transport(
            Arc::new(SleepingDispatcher(
                Duration::from_secs(2),
                json!({ "ok": true }),
            )),
            None,
            Uuid::new_v4(),
        )
        .await;
    assert!(
        result.is_ok(),
        "a tool-stamped timeout_secs with no enforce_timeout marker must not fail a \
         legitimate child: {:?}",
        result.err()
    );
}
