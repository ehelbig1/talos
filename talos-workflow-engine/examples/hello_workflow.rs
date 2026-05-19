//! End-to-end "hello workflow": build a 3-node fan-out DAG, run it
//! through in-memory stubs, print each node's output.
//!
//! Run with:
//!
//! ```text
//! cargo run --example hello_workflow -p talos-workflow-engine
//! ```
//!
//! ## What this demonstrates
//!
//! * Building a graph programmatically via [`WorkflowGraphBuilder`].
//! * Wiring a [`ParallelWorkflowEngine`] with in-memory adapters via
//!   [`minimal_engine`] and overriding the module fetcher with seeded
//!   artifacts.
//! * Scripting worker responses through a [`ScriptedDispatcher`] —
//!   no NATS, no wasm runtime, no network.
//! * Loading the graph into the engine and running it via
//!   [`ParallelWorkflowEngine::run_with_transport`], then reading
//!   per-node outputs from the returned [`WorkflowContext`].
//!
//! Production wire-up looks the same in shape; the differences are
//! which trait impls you plug into `set_module_fetcher`,
//! `set_secrets_resolver`, `set_event_sink`, etc., and which
//! [`NodeDispatcher`] you hand to `run_with_transport` (typically
//! `talos_workflow_engine_nats::NatsNodeDispatcher`).
//!
//! [`WorkflowGraphBuilder`]: talos_workflow_engine::WorkflowGraphBuilder
//! [`ParallelWorkflowEngine`]: talos_workflow_engine::ParallelWorkflowEngine
//! [`minimal_engine`]: talos_workflow_engine_test_utils::minimal_engine
//! [`ScriptedDispatcher`]: talos_workflow_engine_test_utils::dispatch::ScriptedDispatcher
//! [`WorkflowContext`]: talos_workflow_engine_core::WorkflowContext
//! [`NodeDispatcher`]: talos_workflow_engine_core::NodeDispatcher

use std::sync::Arc;

use serde_json::json;
use talos_workflow_engine::{WorkflowEngineError, WorkflowGraphBuilder};
use talos_workflow_engine_core::WasmModuleArtifact;
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher, memory::InMemoryModuleFetcher, minimal_engine,
};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), WorkflowEngineError> {
    // 1. Pick module ids. In a real deployment these come from your
    //    module catalog; here we mint fresh ones because the dispatcher
    //    is mocked and the module bytes never actually execute.
    let fetch_module = Uuid::new_v4();
    let summarize_module = Uuid::new_v4();
    let classify_module = Uuid::new_v4();

    // 2. Build the graph: fetch fans out to summarize + classify.
    //
    //    Why fan-out and not a 2-node linear chain? The engine's
    //    chain optimisation batches in-degree=1 / out-degree=1
    //    sequences into a single pipeline dispatch with its own wire
    //    contract. A fan-out keeps each node on the per-node dispatch
    //    path so the scripted dispatcher's `module_id`-keyed map
    //    resolves cleanly.
    let graph = WorkflowGraphBuilder::new()
        .add_module(
            "fetch",
            fetch_module,
            Some(json!({ "url": "https://example.com" })),
        )
        .add_module("summarize", summarize_module, None)
        .add_module("classify", classify_module, None)
        .edge("fetch", "summarize")
        .edge("fetch", "classify")
        .build()
        .expect("builder inputs are well-formed");

    // 3. Seed the in-memory module fetcher so the engine can resolve
    //    artifacts at dispatch time. The wasm bytes are empty because
    //    the scripted dispatcher short-circuits before any worker
    //    would execute them.
    let fetcher = Arc::new(
        InMemoryModuleFetcher::new()
            .with_module(fetch_module, stub_artifact(fetch_module))
            .with_module(summarize_module, stub_artifact(summarize_module))
            .with_module(classify_module, stub_artifact(classify_module)),
    );

    // 4. Script the dispatcher: each module gets a canned output. A
    //    production NodeDispatcher would forward to a worker pool
    //    over NATS / HTTP / etc; the engine's contract is the same
    //    either way.
    let dispatcher = Arc::new(
        ScriptedDispatcher::new()
            .with_response(fetch_module, json!({ "output": "page contents" }))
            .with_response(
                summarize_module,
                json!({ "output": "two-sentence summary" }),
            )
            .with_response(classify_module, json!({ "output": "category: news" })),
    );

    // 5. Wire the engine. `minimal_engine` supplies in-memory / no-op
    //    impls of every trait; we override the module fetcher with the
    //    seeded one. `worker_shared_key = None` below means the engine
    //    skips secret sealing entirely, so the default secret-envelope
    //    is never invoked.
    let mut engine = minimal_engine();
    engine.set_module_fetcher(fetcher);
    // The engine requires a user context to dispatch — module fetches
    // are scoped to a user, even when the test fetcher ignores it.
    engine.set_user_id(Uuid::new_v4());

    // 6. Load the graph and run.
    let graph_json = serde_json::to_string(&graph).expect("graph serializes");
    engine.load_graph_from_json(&graph_json).await?;

    let context = engine
        .run_with_transport(
            dispatcher,
            /* worker_shared_key */ None,
            Uuid::new_v4(),
        )
        .await?;

    // 7. Print per-node outputs. `node_labels` maps the engine's
    //    internal UUIDs back to the human-readable ids we assigned in
    //    the builder ("fetch" / "summarize").
    println!(
        "workflow finished — {} node outputs:",
        context.results.len()
    );
    for (node_id, output) in &context.results {
        let label = engine
            .node_labels()
            .get(node_id)
            .map(String::as_str)
            .unwrap_or("<unnamed>");
        println!("  {label}: {output}");
    }

    Ok(())
}

/// Build a stub [`WasmModuleArtifact`] for the in-memory fetcher.
///
/// The fields populated are the minimum the engine needs to dispatch a
/// node. `wasm_bytes` is empty — the scripted dispatcher returns its
/// canned response without executing any wasm.
fn stub_artifact(module_id: Uuid) -> WasmModuleArtifact {
    WasmModuleArtifact {
        module_id,
        content_hash: "stub-sha256".into(),
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
