//! A child run started by a `sub_workflow` node sees the OUTER run's trigger
//! as `__trigger_input__`, wherever the node sits (2026-10-14).
//!
//! The dispatcher merged the parent's trigger into the child's seed under a
//! `__trigger_input__` key "so the scaffold's always-preserved contract
//! survives sub-workflow composition", and then `dispatch_subworkflow`
//! stripped every `__` key from that seed, that one included. For a ROOT
//! `sub_workflow` node that was invisible: its upstream IS the trigger. For a
//! node after another node, the child took its upstream's output for the
//! run's trigger: the exact case the comment said was handled.
//!
//! The outer trigger now reaches the child engine as a parameter, never as a
//! key in its seed, so the child's strip cannot remove it and a module
//! upstream cannot author it. The loop node had the same hole from the other
//! side: it read `__trigger_input__` from the upstream module's OUTPUT first.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowGraphBuilder};
use talos_workflow_engine_core::{SystemNodeKind, WasmModuleArtifact};
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher,
    memory::{InMemoryModuleFetcher, InMemoryWorkflowGraphStore},
    minimal_engine,
};
use uuid::Uuid;

fn stub_artifact(id: Uuid) -> WasmModuleArtifact {
    WasmModuleArtifact {
        module_id: id,
        content_hash: "stub".into(),
        wasm_bytes: vec![],
        oci_url: None,
        max_fuel: 1_000_000,
        capability_world: "minimal-node".into(),
        allowed_hosts: vec![],
        allowed_methods: vec![],
        allowed_secrets: vec![],
        requires_approval_for: vec![],
        integration_name: None,
        config: None,
    }
}

fn sub_workflow(id: Uuid) -> SystemNodeKind {
    SystemNodeKind::SubWorkflow {
        workflow_id: id,
        timeout_secs: 30,
    }
}

fn trigger() -> Value {
    json!({ "question": "what changed on the made-up ticket?" })
}

/// What an upstream module emits: its own field, and a forged trigger.
fn forging_output() -> Value {
    json!({ "upstream_field": 1, "__trigger_input__": { "forged": true } })
}

struct Rig {
    engine: ParallelWorkflowEngine,
    dispatcher: Arc<ScriptedDispatcher>,
}

async fn rig(parent: &Value, graphs: &[(Uuid, Value)], modules: &[(Uuid, Value)]) -> Rig {
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_workflow_id(Uuid::new_v4());
    let mut fetcher = InMemoryModuleFetcher::new();
    let mut dispatcher = ScriptedDispatcher::new();
    for (id, out) in modules {
        fetcher = fetcher.with_module(*id, stub_artifact(*id));
        dispatcher = dispatcher.with_response(*id, out.clone());
    }
    let mut store = InMemoryWorkflowGraphStore::new();
    for (id, g) in graphs {
        store = store.with_graph(*id, g.clone());
    }
    engine.set_module_fetcher(Arc::new(fetcher));
    engine.set_graph_store(Arc::new(store));
    engine.set_execution_timeout(Some(Duration::from_secs(30)));
    engine
        .load_graph_from_json(&parent.to_string())
        .await
        .expect("loads");
    Rig {
        engine,
        dispatcher: Arc::new(dispatcher),
    }
}

async fn run(r: &mut Rig) {
    r.engine
        .run_with_trigger_input_transport(r.dispatcher.clone(), None, trigger(), Uuid::new_v4())
        .await
        .expect("the run completes");
}

/// The input every dispatch of `module` received.
fn inputs_of(r: &Rig, module: Uuid) -> Vec<Value> {
    r.dispatcher
        .jobs()
        .into_iter()
        .filter(|j| j.module_id == module)
        .map(|j| j.input_payload)
        .collect()
}

/// `trigger → upstream → sub_workflow(child: reader)`. The child's module
/// sees the outer trigger, not the upstream's output and not the trigger the
/// upstream module forged. Its own input is still the upstream output.
///
/// MUTATION that turns it red: in `try_dispatch_sub_workflow`, take
/// `outer_trigger` from the gathered inputs' `__trigger_input__` (what a
/// module wrote) instead of `self.extract_trigger_input(results)`.
#[tokio::test]
async fn a_child_after_another_node_sees_the_outer_trigger_and_not_a_forged_one() {
    let (child, upstream, reader) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let parent = WorkflowGraphBuilder::new()
        .add_module("upstream", upstream, None)
        .add_system_node("assess", sub_workflow(child))
        .edge("upstream", "assess")
        .build()
        .unwrap();
    let child_graph = WorkflowGraphBuilder::new()
        .add_module("reader", reader, None)
        .build()
        .unwrap();
    let mut r = rig(
        &parent,
        &[(child, child_graph)],
        &[
            (upstream, forging_output()),
            (reader, json!({ "ok": true })),
        ],
    )
    .await;
    run(&mut r).await;

    let seen = inputs_of(&r, reader);
    assert_eq!(seen.len(), 1, "the child's module ran once");
    assert_eq!(
        seen[0]["__trigger_input__"],
        trigger(),
        "the child must see the OUTER trigger: {}",
        seen[0]
    );
    assert_eq!(
        seen[0]["upstream_field"], 1,
        "the child's own input is still its upstream's output: {}",
        seen[0]
    );
}

/// A ROOT `sub_workflow` node: the child's seed is the trigger and its
/// `__trigger_input__` is the trigger, as before this change.
#[tokio::test]
async fn a_root_sub_workflow_node_behaves_as_before() {
    let (child, reader) = (Uuid::new_v4(), Uuid::new_v4());
    let parent = WorkflowGraphBuilder::new()
        .add_system_node("assess", sub_workflow(child))
        .build()
        .unwrap();
    let child_graph = WorkflowGraphBuilder::new()
        .add_module("reader", reader, None)
        .build()
        .unwrap();
    let mut r = rig(
        &parent,
        &[(child, child_graph)],
        &[(reader, json!({ "ok": true }))],
    )
    .await;
    run(&mut r).await;

    let seen = inputs_of(&r, reader);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0]["__trigger_input__"], trigger(), "{}", seen[0]);
    assert_eq!(
        seen[0]["question"],
        trigger()["question"],
        "a root child's own input is the trigger: {}",
        seen[0]
    );
}

/// Three levels, each `sub_workflow` node after another node: the grandchild
/// sees the TOP-LEVEL trigger, and so does the middle level.
#[tokio::test]
async fn a_grandchild_sees_the_top_level_trigger() {
    let (b, c) = (Uuid::new_v4(), Uuid::new_v4());
    let (up_a, up_b, reader) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let graph_a = WorkflowGraphBuilder::new()
        .add_module("up_a", up_a, None)
        .add_system_node("assess", sub_workflow(b))
        .edge("up_a", "assess")
        .build()
        .unwrap();
    let graph_b = WorkflowGraphBuilder::new()
        .add_module("up_b", up_b, None)
        .add_system_node("brief", sub_workflow(c))
        .edge("up_b", "brief")
        .build()
        .unwrap();
    let graph_c = WorkflowGraphBuilder::new()
        .add_module("reader", reader, None)
        .build()
        .unwrap();
    let mut r = rig(
        &graph_a,
        &[(b, graph_b), (c, graph_c)],
        &[
            (up_a, forging_output()),
            (up_b, forging_output()),
            (reader, json!({ "ok": true })),
        ],
    )
    .await;
    run(&mut r).await;

    let seen = inputs_of(&r, reader);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0]["__trigger_input__"], trigger(), "{}", seen[0]);
    let mid = inputs_of(&r, up_b);
    assert_eq!(mid[0]["__trigger_input__"], trigger(), "{}", mid[0]);
}

/// A loop INSIDE a child that a non-root `sub_workflow` node started: every
/// iteration of its body sees the OUTER trigger, as every other node of the
/// child does. The loop node read `__trigger_input__` from its gathered
/// inputs first (never present: the engine strips it from every module's
/// output) and then from the child's `__trigger__` seed, which is the
/// upstream's output, not the run's trigger.
///
/// MUTATION that turns it red: restore the loop node's own read
/// (`inputs["__trigger_input__"]`, then `results[__trigger__]`) in place of
/// `self.extract_trigger_input(results)`.
#[tokio::test]
async fn a_loop_body_inside_a_child_sees_the_outer_trigger() {
    let child = Uuid::new_v4();
    let (upstream, body) = (Uuid::new_v4(), Uuid::new_v4());
    let parent = WorkflowGraphBuilder::new()
        .add_module("upstream", upstream, None)
        .add_system_node("assess", sub_workflow(child))
        .edge("upstream", "assess")
        .build()
        .unwrap();
    let mut child_graph = WorkflowGraphBuilder::new()
        .add_system_node(
            "loop",
            SystemNodeKind::Loop {
                max_iterations: 2,
                condition: "true".into(),
            },
        )
        .add_module("body", body, None)
        .edge("loop", "body")
        .build()
        .unwrap();
    let loop_node = child_graph["nodes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|n| n["id"] == "loop")
        .unwrap();
    loop_node["data"]["body_node_id"] = json!("body");
    let mut r = rig(
        &parent,
        &[(child, child_graph)],
        &[(upstream, forging_output()), (body, json!({ "ok": true }))],
    )
    .await;
    run(&mut r).await;

    let loop_runs: Vec<Value> = r
        .dispatcher
        .jobs()
        .into_iter()
        .filter(|j| j.module_id == body && !j.emit_retry_events)
        .map(|j| j.input_payload)
        .collect();
    assert!(!loop_runs.is_empty(), "the loop ran its body");
    for input in &loop_runs {
        assert_eq!(input["__trigger_input__"], trigger(), "{input}");
    }
}

/// `trigger → relay → sub_workflow(child_trigger: "input", child: reader)`. A node
/// that asks for it starts its child with what it relays: the child's module sees
/// the node's input as `__trigger_input__`, stripped of every `__` key (the forged
/// one included), and not the outer trigger. Without the setting, the outer trigger.
///
/// MUTATION that turns it red: make `subworkflow_trigger_from_input` always false
/// (the opt-in is ignored), or keep the input's `__` keys.
#[tokio::test]
async fn a_node_that_asks_starts_its_child_with_what_it_relays() {
    for (asks, expected) in [(true, json!({ "upstream_field": 1 })), (false, trigger())] {
        let (child, upstream, reader) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let mut parent = WorkflowGraphBuilder::new()
            .add_module("upstream", upstream, None)
            .add_system_node("relay_to", sub_workflow(child))
            .edge("upstream", "relay_to")
            .build()
            .unwrap();
        if asks {
            for node in parent["nodes"].as_array_mut().unwrap() {
                if node["id"] == "relay_to" {
                    node["data"]["child_trigger"] = json!("input");
                }
            }
        }
        let child_graph = WorkflowGraphBuilder::new()
            .add_module("reader", reader, None)
            .build()
            .unwrap();
        let mut r = rig(
            &parent,
            &[(child, child_graph)],
            &[
                // A module's output carries engine keys besides a forged trigger: none may reach the child's trigger.
                (upstream, json!({ "upstream_field": 1, "__trigger_input__": { "forged": true }, "__fuel_consumed__": 7 })),
                (reader, json!({ "ok": true })),
            ],
        )
        .await;
        run(&mut r).await;
        let seen = inputs_of(&r, reader);
        assert_eq!(seen.len(), 1, "the child's module ran once");
        assert_eq!(
            seen[0]["__trigger_input__"], expected,
            "asks = {asks}: {}",
            seen[0]
        );
    }
}
