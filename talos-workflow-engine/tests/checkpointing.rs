//! Opt-in per-node checkpointing (Phase C, 2026-05-28).
//!
//! Locks in the contract of [`ParallelWorkflowEngine::set_checkpoint_store`]:
//!
//! 1. With a store wired (`every_n = 1`), every node completion persists a
//!    snapshot of ALL completed-node outputs, so the final snapshot is a
//!    complete map of the run.
//! 2. The persisted snapshot is shaped exactly like a resume seed — feeding
//!    `store.load(exec_id)` back into `run_with_seed_with_transport` causes
//!    the engine to treat those nodes as already-done and NOT re-dispatch
//!    them. This is the crash-recovery path: a controller restart resumes
//!    from the last checkpoint instead of from scratch.
//! 3. Default (no store wired, or `every_n = 0`) is a no-op — exactly the
//!    pre-Phase-C behaviour, with zero writes.
//!
//! A fan-out graph is used (not a linear chain) so the pipeline-chain
//! optimiser doesn't batch nodes — each node is its own dispatch unit and
//! flows through `handle_node_success`, the checkpoint seam.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowGraphBuilder};
use talos_workflow_engine_core::{CheckpointStore, WasmModuleArtifact};
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher,
    memory::{InMemoryCheckpointStore, InMemoryModuleFetcher},
    minimal_engine,
};
use uuid::Uuid;

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

/// Fan-out graph: `start ─→ a`, `start ─→ b`. Three module nodes, no
/// linear chain, so each completes via `handle_node_success`.
fn build_fanout() -> (serde_json::Value, Uuid, Uuid, Uuid) {
    let start = Uuid::new_v4();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module("start", start, None)
        .add_module("a", a, None)
        .add_module("b", b, None)
        .edge("start", "a")
        .edge("start", "b")
        .build()
        .expect("graph builds");
    (graph, start, a, b)
}

fn engine_with(start: Uuid, a: Uuid, b: Uuid) -> ParallelWorkflowEngine {
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new()
            .with_module(start, stub_artifact(start))
            .with_module(a, stub_artifact(a))
            .with_module(b, stub_artifact(b)),
    ));
    engine
}

fn dispatcher(start: Uuid, a: Uuid, b: Uuid) -> Arc<ScriptedDispatcher> {
    Arc::new(
        ScriptedDispatcher::new()
            .with_response(start, json!({"output": "start"}))
            .with_response(a, json!({"output": "a"}))
            .with_response(b, json!({"output": "b"})),
    )
}

/// Checkpoint saves are spawned (the completion handler must not block on
/// I/O), so poll the store for up to ~1s until it holds `expected` nodes.
async fn poll_until_len(store: &InMemoryCheckpointStore, exec_id: Uuid, expected: usize) -> usize {
    for _ in 0..100 {
        let n = store.load(exec_id).await.expect("load").len();
        if n >= expected {
            return n;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    store.load(exec_id).await.expect("load").len()
}

#[tokio::test]
async fn checkpointing_persists_all_completed_node_outputs() {
    let (graph_json, start, a, b) = build_fanout();
    let mut engine = engine_with(start, a, b);
    let store = InMemoryCheckpointStore::new();
    engine.set_checkpoint_store(Arc::new(store.clone()), 1);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("graph loads");

    let exec_id = Uuid::new_v4();
    let ctx = engine
        .run_with_transport(dispatcher(start, a, b), None, exec_id)
        .await
        .expect("run completes");
    assert!(!ctx.waiting, "run should complete, not pause");

    let n = poll_until_len(&store, exec_id, 3).await;
    assert_eq!(n, 3, "snapshot must hold all 3 completed nodes");

    // Snapshot is keyed by the engine's node ids and carries each output.
    let snap = store.load(exec_id).await.expect("load");
    let id = |label: &str| -> Uuid {
        engine
            .node_labels()
            .iter()
            .find_map(|(id, l)| (l == label).then_some(*id))
            .expect("label exists")
    };
    for label in ["start", "a", "b"] {
        assert!(
            snap.contains_key(&id(label)),
            "checkpoint missing node {label}: {snap:?}"
        );
    }
}

#[tokio::test]
async fn checkpointing_disabled_by_default_writes_nothing() {
    let (graph_json, start, a, b) = build_fanout();
    let mut engine = engine_with(start, a, b);
    // Store wired but cadence 0 => disabled (set_checkpoint_store clears it).
    let store = InMemoryCheckpointStore::new();
    engine.set_checkpoint_store(Arc::new(store.clone()), 0);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("graph loads");

    let exec_id = Uuid::new_v4();
    engine
        .run_with_transport(dispatcher(start, a, b), None, exec_id)
        .await
        .expect("run completes");

    // Give any (incorrectly) spawned save a chance to land, then assert none did.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        store.is_empty(),
        "every_n=0 must disable checkpointing — store should be empty"
    );
}

#[tokio::test]
async fn checkpoint_snapshot_is_a_valid_resume_seed() {
    // The crash-recovery contract: a snapshot written during run 1 fed back
    // as the seed for run 2 makes the engine skip re-dispatching the
    // already-completed nodes.
    let (graph_json, start, a, b) = build_fanout();
    let mut engine = engine_with(start, a, b);
    let store = InMemoryCheckpointStore::new();
    engine.set_checkpoint_store(Arc::new(store.clone()), 1);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph_json).unwrap())
        .await
        .expect("graph loads");

    let exec_id = Uuid::new_v4();
    let d1 = dispatcher(start, a, b);
    engine
        .run_with_transport(d1.clone(), None, exec_id)
        .await
        .expect("run 1 completes");
    poll_until_len(&store, exec_id, 3).await;

    // Resume from the checkpoint with a FRESH dispatcher whose counters
    // start at zero. Seeded nodes must not be re-dispatched.
    let seed = store.load(exec_id).await.expect("load");
    let d2 = dispatcher(start, a, b);
    let resume = engine
        .run_with_seed_with_transport(d2.clone(), None, seed, exec_id)
        .await
        .expect("resume completes");
    assert!(!resume.waiting);

    for (label, module) in [("start", start), ("a", a), ("b", b)] {
        assert_eq!(
            d2.dispatch_count(module),
            0,
            "node {label} was checkpointed; resume must not re-dispatch it"
        );
    }
}
