//! Pre-dispatch sanity checks on the engine's run wrappers.
//!
//! Both `run_with_transport` and `run_with_seed_with_transport`
//! short-circuit with a typed `WorkflowEngineError` variant before
//! they reach the reactor when the engine is misconfigured. The
//! checks let downstream callers `match` on the variant instead of
//! parsing the catch-all `Execution(String)` failure that used to
//! surface for these conditions deep in per-node dispatch.
//!
//! Order of evaluation (locked in by `precheck_runnable`):
//!
//! 1. `SecretsResolverMissing` — universal precondition.
//! 2. `ModuleFetcherMissing` — only when the graph has module-backed
//!    nodes.
//! 3. `UserContextRequired` — same scope as the fetcher check.
//! 4. `GraphCyclic` — last because the cycle scan is the most
//!    expensive of the four.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowEngineError, WorkflowGraphBuilder};
use talos_workflow_engine_core::{SystemNodeKind, WasmModuleArtifact};
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

#[tokio::test]
async fn module_fetcher_missing_fails_with_typed_error() {
    // A graph with at least one module-backed node and no fetcher
    // wired must fail at the wrapper boundary, not deep inside the
    // reactor. Locks in the typed-error variant so downstream callers
    // can match on it rather than scraping a string.
    let module_id = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module("only", module_id, None)
        .build()
        .unwrap();

    let mut engine = ParallelWorkflowEngine::new();
    // Wire only the secrets resolver (the very first guard) so we
    // exercise the *next* check — the fetcher one.
    engine.set_secrets_resolver(Arc::new(
        talos_workflow_engine_test_utils::memory::InMemorySecretsResolver::new(),
    ));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .unwrap();

    let dispatcher = Arc::new(ScriptedDispatcher::new());
    let err = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect_err("must fail at the precheck");
    assert!(
        matches!(err, WorkflowEngineError::ModuleFetcherMissing),
        "expected ModuleFetcherMissing, got: {err:?}"
    );
}

#[tokio::test]
async fn user_context_required_fails_with_typed_error() {
    // Same shape as the fetcher test but the fetcher *is* wired —
    // the user_id is what's missing. Order matters: this check runs
    // after the fetcher check, so we have to set the fetcher to
    // reach this guard.
    let module_id = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module("only", module_id, None)
        .build()
        .unwrap();

    let mut engine = minimal_engine(); // wires resolver + fetcher
                                       // Override the in-memory fetcher with a seeded one so we don't
                                       // depend on minimal_engine's empty default — the *check* fires
                                       // before the fetcher is asked to resolve anything, but be
                                       // explicit about state.
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new().with_module(module_id, stub_artifact(module_id)),
    ));
    // Crucially, do NOT set_user_id.
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .unwrap();

    let dispatcher = Arc::new(ScriptedDispatcher::new());
    let err = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect_err("must fail at the precheck");
    assert!(
        matches!(err, WorkflowEngineError::UserContextRequired),
        "expected UserContextRequired, got: {err:?}"
    );
}

#[tokio::test]
async fn pure_system_node_graph_runs_without_fetcher_or_user() {
    // The fetcher / user-id checks are SCOPED — they only fire when
    // the graph references a module-backed node. A graph composed
    // entirely of system nodes (no module dispatch, no user
    // attribution) is still runnable. This test guards against an
    // over-eager precheck that would block legitimate use cases.
    let graph = WorkflowGraphBuilder::new()
        .add_system_node("collect", SystemNodeKind::Collect)
        .build()
        .unwrap();

    let mut engine = ParallelWorkflowEngine::new();
    engine.set_secrets_resolver(Arc::new(
        talos_workflow_engine_test_utils::memory::InMemorySecretsResolver::new(),
    ));
    // No fetcher, no user_id, no module-backed nodes — must still run.
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .unwrap();

    let dispatcher = Arc::new(ScriptedDispatcher::new());
    let ctx = engine
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect("pure-system graph must be runnable");
    assert_eq!(ctx.results.len(), 1);
}

#[tokio::test]
async fn precheck_runs_on_seeded_resume_path_too() {
    // The seeded path uses the same precheck. Without this regression
    // guard, a config error could slip through `run_with_seed_with_transport`
    // and surface as a per-node failure on resume — exactly what the
    // typed variants exist to prevent.
    let module_id = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module("only", module_id, None)
        .build()
        .unwrap();

    let mut engine = ParallelWorkflowEngine::new();
    engine.set_secrets_resolver(Arc::new(
        talos_workflow_engine_test_utils::memory::InMemorySecretsResolver::new(),
    ));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .unwrap();

    let dispatcher = Arc::new(ScriptedDispatcher::new().with_response(module_id, json!({})));
    let err = engine
        .run_with_seed_with_transport(dispatcher, None, HashMap::new(), Uuid::new_v4())
        .await
        .expect_err("must fail at the precheck");
    assert!(matches!(err, WorkflowEngineError::ModuleFetcherMissing));
}
