//! A module can tell how its run was started: `__started_by__ = {"kind"}`
//! (2026-10-14).
//!
//! `list_executions` recorded `started_by.kind` and no module ever saw it. A
//! step log meant to count only the owner's taps counted every run, and test
//! runs had to opt out with a field of the workflow author's own.
//!
//! The engine reads the kind once when a top-level run starts (a
//! `StartedByResolver` port; the controller's reads the execution row) and
//! writes it set-or-REMOVE onto every module dispatch. Kind only. A child run
//! carries its parent's. It is on the engine-authored strip list, so a trigger
//! payload or a module's output cannot supply it.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowGraphBuilder};
use talos_workflow_engine_core::{StartedByResolver, SystemNodeKind, WasmModuleArtifact};
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher,
    memory::{InMemoryModuleFetcher, InMemoryWorkflowGraphStore},
    minimal_engine,
};
use uuid::Uuid;

/// Answers one kind for every execution, and counts how often it is asked.
struct FixedKind(Option<&'static str>, std::sync::atomic::AtomicUsize);

#[async_trait]
impl StartedByResolver for FixedKind {
    async fn started_by_kind(&self, _execution_id: Uuid, _user: Option<Uuid>) -> Option<String> {
        self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.0.map(str::to_string)
    }
}

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

struct Rig {
    engine: ParallelWorkflowEngine,
    dispatcher: Arc<ScriptedDispatcher>,
    resolver: Arc<FixedKind>,
}

async fn rig(
    graph: &Value,
    children: &[(Uuid, Value)],
    modules: &[(Uuid, Value)],
    kind: Option<&'static str>,
) -> Rig {
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_workflow_id(Uuid::new_v4());
    let resolver = Arc::new(FixedKind(kind, std::sync::atomic::AtomicUsize::new(0)));
    engine.set_started_by_resolver(resolver.clone());
    let mut fetcher = InMemoryModuleFetcher::new();
    let mut dispatcher = ScriptedDispatcher::new();
    for (id, out) in modules {
        fetcher = fetcher.with_module(*id, stub_artifact(*id));
        dispatcher = dispatcher.with_response(*id, out.clone());
    }
    let mut store = InMemoryWorkflowGraphStore::new();
    for (id, g) in children {
        store = store.with_graph(*id, g.clone());
    }
    engine.set_module_fetcher(Arc::new(fetcher));
    engine.set_graph_store(Arc::new(store));
    engine.set_execution_timeout(Some(Duration::from_secs(30)));
    engine
        .load_graph_from_json(&graph.to_string())
        .await
        .expect("loads");
    Rig {
        engine,
        dispatcher: Arc::new(dispatcher),
        resolver,
    }
}

async fn run(r: &mut Rig, trigger: Value) {
    r.engine
        .run_with_trigger_input_transport(r.dispatcher.clone(), None, trigger, Uuid::new_v4())
        .await
        .expect("the run completes");
}

fn inputs_of(r: &Rig, module: Uuid) -> Vec<Value> {
    r.dispatcher
        .jobs()
        .into_iter()
        .filter(|j| j.module_id == module)
        .map(|j| j.input_payload)
        .collect()
}

fn two_nodes(first: Uuid, second: Uuid) -> Value {
    WorkflowGraphBuilder::new()
        .add_module("first", first, None)
        .add_module("second", second, None)
        .edge("first", "second")
        .build()
        .unwrap()
}

/// Every module of the run receives the kind the run's row records, and the
/// row is read once per run, not per node.
#[tokio::test]
async fn every_module_receives_the_runs_start_kind() {
    for kind in ["action_link", "manual", "schedule", "webhook", "test"] {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut r = rig(
            &two_nodes(a, b),
            &[],
            &[(a, json!({"ok": 1})), (b, json!({"ok": 2}))],
            Some(kind),
        )
        .await;
        run(&mut r, json!({"q": 1})).await;
        for m in [a, b] {
            let seen = inputs_of(&r, m);
            assert_eq!(seen[0]["__started_by__"], json!({ "kind": kind }), "{kind}");
        }
        assert_eq!(
            r.resolver.1.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "{kind}: read once per run"
        );
    }
}

/// A child run carries its parent's kind, and never reads a row (its engine
/// runs under a synthetic execution id that names none).
#[tokio::test]
async fn a_child_run_carries_its_parents_start_kind() {
    let (child, up, reader) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let parent = WorkflowGraphBuilder::new()
        .add_module("up", up, None)
        .add_system_node(
            "assess",
            SystemNodeKind::SubWorkflow {
                workflow_id: child,
                timeout_secs: 30,
            },
        )
        .edge("up", "assess")
        .build()
        .unwrap();
    let child_graph = WorkflowGraphBuilder::new()
        .add_module("reader", reader, None)
        .build()
        .unwrap();
    let mut r = rig(
        &parent,
        &[(child, child_graph)],
        &[(up, json!({"ok": 1})), (reader, json!({"ok": 2}))],
        Some("action_link"),
    )
    .await;
    run(&mut r, json!({})).await;
    assert_eq!(
        inputs_of(&r, reader)[0]["__started_by__"],
        json!({ "kind": "action_link" })
    );
    assert_eq!(r.resolver.1.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// A trigger payload carrying `__started_by__` cannot pass for the engine's:
/// with nothing resolved, no module sees the key, at the root or inside
/// `__trigger_input__`.
///
/// MUTATION that turns it red: take `STARTED_BY` off
/// `ENGINE_AUTHORED_INPUT_KEYS` (the trigger keeps it, and every node reads
/// it inside `__trigger_input__`).
#[tokio::test]
async fn a_trigger_cannot_supply_the_start_kind() {
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let mut r = rig(
        &two_nodes(a, b),
        &[],
        &[(a, json!({"ok": 1})), (b, json!({"ok": 2}))],
        None,
    )
    .await;
    run(
        &mut r,
        json!({ "q": 1, "__started_by__": { "kind": "action_link" } }),
    )
    .await;
    for m in [a, b] {
        let seen = &inputs_of(&r, m)[0];
        assert!(seen.get("__started_by__").is_none(), "{seen}");
        assert!(
            seen["__trigger_input__"].get("__started_by__").is_none(),
            "{seen}"
        );
    }
}

/// A module's output carrying `__started_by__` does not reach the node after
/// it: with nothing resolved the next node has no key; with a kind resolved,
/// it has the engine's.
///
/// MUTATION that turns it red: take `STARTED_BY` off the strip list AND make
/// `apply_started_by` set-or-inherit (insert only when a kind is known) —
/// the two belts this key has, removed together.
#[tokio::test]
async fn a_modules_output_cannot_supply_the_start_kind() {
    for (resolved, expected) in [
        (None, None),
        (Some("schedule"), Some(json!({ "kind": "schedule" }))),
    ] {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut r = rig(
            &two_nodes(a, b),
            &[],
            &[
                (
                    a,
                    json!({ "ok": 1, "__started_by__": { "kind": "action_link" } }),
                ),
                (b, json!({ "ok": 2 })),
            ],
            resolved,
        )
        .await;
        run(&mut r, json!({})).await;
        let seen = &inputs_of(&r, b)[0];
        assert_eq!(seen.get("__started_by__").cloned(), expected, "{seen}");
    }
}

/// The kind is bounded: a row something else wrote cannot put an unbounded
/// string into every node's input.
#[tokio::test]
async fn an_overlong_kind_is_capped() {
    let a = Uuid::new_v4();
    let long: &'static str = Box::leak("k".repeat(500).into_boxed_str());
    let graph = WorkflowGraphBuilder::new()
        .add_module("only", a, None)
        .build()
        .unwrap();
    let mut r = rig(&graph, &[], &[(a, json!({}))], Some(long)).await;
    run(&mut r, json!({})).await;
    let kind = inputs_of(&r, a)[0]["__started_by__"]["kind"]
        .as_str()
        .unwrap()
        .chars()
        .count();
    assert_eq!(
        kind,
        talos_workflow_engine_core::reserved_keys::STARTED_BY_KIND_MAX_CHARS
    );
}
