//! Pause-and-resume across two engine runs, end-to-end.
//!
//! Run with:
//!
//! ```text
//! cargo run --example checkpoint_resume -p talos-workflow-engine
//! ```
//!
//! ## What this demonstrates
//!
//! * Implementing [`CheckpointStore`] with a plain `Mutex<HashMap>` —
//!   no database required.
//! * Implementing [`NodeLifecycleHook`] to snapshot each node's output
//!   into the store the moment the engine emits it.
//! * Implementing a small custom [`NodeDispatcher`] that simulates a
//!   transient failure on the first run, then succeeds on the second.
//! * Running the workflow twice with the **same** `execution_id`:
//!   - First call uses [`run_with_transport`] (fresh start). It fails
//!     mid-graph, but the prefix is checkpointed.
//!   - Second call uses [`run_with_seed_with_transport`] with the
//!     checkpoint as the seed map. The engine treats the seeded nodes
//!     as completed and only re-dispatches what's left.
//!
//! ## A note on the graph shape
//!
//! The graph is fan-out / fan-in (`root → {branch-a, branch-b} →
//! aggregate`) rather than linear (`root → branch → aggregate`)
//! because the engine's pipeline-chain optimization batches `in=1 /
//! out=1` sequences into a single `dispatch_chain` call whose
//! per-step `DispatchJob.module_id` is set to the **node** id, not
//! the resolved module id. A dispatcher that switches behaviour by
//! `module_id` (this example, the `hello_workflow` example, and the
//! workflow-timeout integration tests all do) wouldn't match. Fan-out
//! keeps every node on the per-node dispatch path.
//!
//! Production wire-up looks the same; swap the in-memory store for
//! Postgres / S3 / your blob store of choice. The trait surface is
//! the contract; the storage is yours.
//!
//! [`CheckpointStore`]: talos_workflow_engine_core::CheckpointStore
//! [`NodeLifecycleHook`]: talos_workflow_engine_core::NodeLifecycleHook
//! [`NodeDispatcher`]: talos_workflow_engine_core::NodeDispatcher
//! [`run_with_transport`]: talos_workflow_engine::ParallelWorkflowEngine::run_with_transport
//! [`run_with_seed_with_transport`]: talos_workflow_engine::ParallelWorkflowEngine::run_with_seed_with_transport

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{json, Value as JsonValue};
use talos_workflow_engine::{WorkflowEngineError, WorkflowGraphBuilder};
use talos_workflow_engine_core::{
    BoxError, CheckpointStore, DispatchJob, DispatchResult, NodeCompletionContext, NodeDispatcher,
    NodeLifecycleHook, WasmModuleArtifact,
};
use talos_workflow_engine_test_utils::{memory::InMemoryModuleFetcher, minimal_engine};
use tokio::task::JoinHandle;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), WorkflowEngineError> {
    // Distinct module ids per node so the dispatcher can switch on
    // `job.module_id`. See the file-level note about chain detection
    // for why we avoid `root → branch → aggregate` linearity.
    let root_module = Uuid::new_v4();
    let branch_a_module = Uuid::new_v4();
    let branch_b_module = Uuid::new_v4();
    let aggregate_module = Uuid::new_v4();

    let graph = WorkflowGraphBuilder::new()
        .add_module("root", root_module, None)
        .add_module("branch-a", branch_a_module, None)
        .add_module("branch-b", branch_b_module, None)
        .add_module("aggregate", aggregate_module, None)
        .edge("root", "branch-a")
        .edge("root", "branch-b")
        .edge("branch-a", "aggregate")
        .edge("branch-b", "aggregate")
        .build()
        .expect("graph well-formed");

    let store: Arc<dyn CheckpointStore> = Arc::new(InMemoryCheckpointStore::default());
    let execution_id = Uuid::new_v4();

    // ── Run 1: fresh start, branch-b fails ──────────────────────────
    println!("── Run 1: fresh start ──");
    let dispatcher_1 = Arc::new(FlakyDispatcher {
        fail_module: branch_b_module,
    });
    let (result_1, hook_1) =
        run_once(graph.clone(), store.clone(), dispatcher_1, execution_id).await;
    match &result_1 {
        Ok(_) => panic!("Run 1 was supposed to fail (branch-b is flaky)"),
        Err(e) => println!("  expected failure: {e}"),
    }

    // The hook spawns each save on a tokio task to honour the
    // "MUST return quickly" contract on `NodeLifecycleHook`. After the
    // workflow returns we drain those tasks so the snapshot we read
    // back from the store is complete — without this, the in-flight
    // save for any concurrently-completed node could race the load.
    hook_1.flush().await;

    let snapshot = store.load(execution_id).await.expect("checkpoint loads");
    println!(
        "  checkpoint captured {} node output(s) before failure:",
        snapshot.len()
    );
    for id in snapshot.keys() {
        println!("    {id}");
    }

    // ── Run 2: same execution_id, seeded with the checkpoint ────────
    // The dispatcher is no longer flaky — branch-b succeeds (or,
    // equivalently, the operator deployed a fix). The engine treats
    // every seeded node as completed and only dispatches what's left:
    // branch-b (not seeded; was the failing one) and aggregate (its
    // dependencies are now satisfied by seed + branch-b's output).
    println!("── Run 2: resume from checkpoint ──");
    let dispatcher_2 = Arc::new(WorkingDispatcher);
    let (result_2, hook_2) =
        run_resume(graph, store.clone(), dispatcher_2, execution_id, snapshot).await;
    let labelled = result_2?;
    hook_2.flush().await;

    println!(
        "  workflow finished — {} total node output(s):",
        labelled.len()
    );
    let mut keys: Vec<&String> = labelled.keys().collect();
    keys.sort();
    for label in keys {
        println!("    {label}: {}", labelled[label]);
    }

    Ok(())
}

// ── Helpers: build, wire, run ──────────────────────────────────────

async fn run_once(
    graph: JsonValue,
    store: Arc<dyn CheckpointStore>,
    dispatcher: Arc<dyn NodeDispatcher>,
    execution_id: Uuid,
) -> (
    Result<HashMap<String, JsonValue>, WorkflowEngineError>,
    Arc<CheckpointingHook>,
) {
    let (mut engine, hook) = wire_engine(&graph, store, execution_id);
    if let Err(e) = engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
    {
        return (Err(e), hook);
    }
    match engine
        .run_with_transport(dispatcher, None, execution_id)
        .await
    {
        Ok(context) => (
            Ok(label_outputs(&context.results, engine.node_labels())),
            hook,
        ),
        Err(e) => (Err(e), hook),
    }
}

async fn run_resume(
    graph: JsonValue,
    store: Arc<dyn CheckpointStore>,
    dispatcher: Arc<dyn NodeDispatcher>,
    execution_id: Uuid,
    seed: HashMap<Uuid, JsonValue>,
) -> (
    Result<HashMap<String, JsonValue>, WorkflowEngineError>,
    Arc<CheckpointingHook>,
) {
    let (mut engine, hook) = wire_engine(&graph, store, execution_id);
    if let Err(e) = engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
    {
        return (Err(e), hook);
    }
    match engine
        .run_with_seed_with_transport(dispatcher, None, seed, execution_id)
        .await
    {
        Ok(context) => (
            Ok(label_outputs(&context.results, engine.node_labels())),
            hook,
        ),
        Err(e) => (Err(e), hook),
    }
}

fn wire_engine(
    graph: &JsonValue,
    store: Arc<dyn CheckpointStore>,
    execution_id: Uuid,
) -> (
    talos_workflow_engine::ParallelWorkflowEngine,
    Arc<CheckpointingHook>,
) {
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());

    // Seed the module fetcher with stub artifacts for every module the
    // graph references. The dispatcher short-circuits before any wasm
    // runs, so `wasm_bytes` is empty.
    let mut fetcher = InMemoryModuleFetcher::new();
    for module_id in module_ids(graph) {
        fetcher = fetcher.with_module(module_id, stub_artifact(module_id));
    }
    engine.set_module_fetcher(Arc::new(fetcher));

    // Snapshot every node output as it lands. The hook is sync, so it
    // tokio::spawns the actual save — see the trait docs.
    let hook = Arc::new(CheckpointingHook {
        store,
        execution_id,
        snapshot: Arc::new(Mutex::new(HashMap::new())),
        in_flight: Arc::new(Mutex::new(Vec::new())),
    });
    engine.set_node_hook(hook.clone());

    (engine, hook)
}

// ── In-memory CheckpointStore ──────────────────────────────────────

#[derive(Default)]
struct InMemoryCheckpointStore {
    /// Outer Mutex so the trait can stay `&self`. Inner map keyed on
    /// execution id — mirrors the on-disk shape of a Postgres impl
    /// (one row per execution).
    runs: Mutex<HashMap<Uuid, HashMap<Uuid, JsonValue>>>,
}

#[async_trait]
impl CheckpointStore for InMemoryCheckpointStore {
    async fn load(&self, execution_id: Uuid) -> Result<HashMap<Uuid, JsonValue>, BoxError> {
        // Empty map = no checkpoint (per the trait contract); the
        // engine treats that the same as a fresh run.
        let runs = self.runs.lock().expect("checkpoint store lock");
        Ok(runs.get(&execution_id).cloned().unwrap_or_default())
    }

    async fn save(&self, execution_id: Uuid, snapshot: &JsonValue) -> Result<(), BoxError> {
        let object = snapshot
            .as_object()
            .ok_or_else(|| -> BoxError { "snapshot must be a JSON object".into() })?;

        let mut parsed = HashMap::with_capacity(object.len());
        for (key, value) in object {
            let id = Uuid::parse_str(key)
                .map_err(|e| -> BoxError { format!("bad node id {key}: {e}").into() })?;
            parsed.insert(id, value.clone());
        }

        let mut runs = self.runs.lock().expect("checkpoint store lock");
        runs.insert(execution_id, parsed);
        Ok(())
    }
}

// ── Hook that snapshots every completed node ───────────────────────

struct CheckpointingHook {
    store: Arc<dyn CheckpointStore>,
    execution_id: Uuid,
    /// Accumulator for the current run. Built up node-by-node and
    /// persisted on each completion, so the on-disk snapshot always
    /// reflects the latest committed state.
    snapshot: Arc<Mutex<HashMap<Uuid, JsonValue>>>,
    /// Tracks every spawned save so the caller can `flush().await`
    /// after the run returns and be sure no save is still in flight.
    /// Without this, a save spawned for one branch could lose to a
    /// failure on a sibling branch — the workflow returns Err before
    /// the spawn lands and the read-back snapshot is short.
    in_flight: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl CheckpointingHook {
    /// Wait for every save spawned during this run to complete. Call
    /// after the engine's `run_*` returns and before reading the store.
    async fn flush(&self) {
        let handles: Vec<JoinHandle<()>> = {
            let mut guard = self.in_flight.lock().expect("in_flight lock");
            std::mem::take(&mut *guard)
        };
        for handle in handles {
            let _ = handle.await;
        }
    }
}

impl NodeLifecycleHook for CheckpointingHook {
    fn on_node_completed(&self, ctx: NodeCompletionContext<'_>, output: &JsonValue) {
        // Build the next snapshot under the lock, then persist on a
        // spawned task so this sync method returns quickly. The trait
        // explicitly forbids blocking I/O inline.
        let next = {
            let mut snap = self.snapshot.lock().expect("snapshot lock");
            snap.insert(ctx.node_id, output.clone());
            snap.clone()
        };
        let blob = JsonValue::Object(next.into_iter().map(|(k, v)| (k.to_string(), v)).collect());
        let store = Arc::clone(&self.store);
        let execution_id = self.execution_id;
        let handle = tokio::spawn(async move {
            if let Err(e) = store.save(execution_id, &blob).await {
                eprintln!("checkpoint save failed: {e}");
            }
        });
        if let Ok(mut guard) = self.in_flight.lock() {
            guard.push(handle);
        }
    }
}

// ── Two dispatchers: the flaky one and the working one ─────────────

/// Returns success for everything except `fail_module`, which sleeps
/// briefly and then errors. The sleep gives the engine a chance to
/// observe other concurrent dispatches' successes (and run their
/// `on_node_completed` hook) before the failure trips the workflow —
/// a more realistic production scenario than racing every concurrent
/// future to a tie.
struct FlakyDispatcher {
    fail_module: Uuid,
}

#[async_trait]
impl NodeDispatcher for FlakyDispatcher {
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError> {
        if job.module_id == self.fail_module {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            return Err("worker pool degraded; please retry".into());
        }
        Ok(DispatchResult {
            output: json!({ "module": job.module_id, "stage": "ok" }),
        })
    }
}

/// Always succeeds. Stand-in for "the worker pool recovered."
struct WorkingDispatcher;

#[async_trait]
impl NodeDispatcher for WorkingDispatcher {
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError> {
        Ok(DispatchResult {
            output: json!({ "module": job.module_id, "stage": "ok" }),
        })
    }
}

// ── Plumbing helpers ───────────────────────────────────────────────

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

fn module_ids(graph: &JsonValue) -> Vec<Uuid> {
    let mut ids = Vec::new();
    if let Some(nodes) = graph.get("nodes").and_then(|n| n.as_array()) {
        for node in nodes {
            if let Some(s) = node.get("type").and_then(|v| v.as_str()) {
                if let Ok(id) = Uuid::parse_str(s) {
                    ids.push(id);
                }
            }
        }
    }
    ids.sort();
    ids.dedup();
    ids
}

fn label_outputs(
    results: &HashMap<Uuid, JsonValue>,
    labels: &HashMap<Uuid, String>,
) -> HashMap<String, JsonValue> {
    results
        .iter()
        .map(|(id, v)| {
            let label = labels.get(id).cloned().unwrap_or_else(|| id.to_string());
            (label, v.clone())
        })
        .collect()
}
