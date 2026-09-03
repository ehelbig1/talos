//! A sub-workflow's per-node rollups must be attributed to the SUB-WORKFLOW.
//!
//! `NodeCompletionContext.workflow_id` is what the controller's node hook
//! writes into `execution_cost_rollup.workflow_id` (and, on failure, into
//! `dead_letter_queue.workflow_id`). The engine builds it as
//! `self.workflow_id.unwrap_or(execution_id)`, and a sub-engine built from
//! `adapter_set()` carries no workflow id at all — so before this fix every
//! sub-workflow node's rollup row was stamped with the synthetic per-run uuid
//! `execute_subworkflow_graph` seeds.
//!
//! That is not a cosmetic mis-labelling. No `workflows` row has that id, and
//! the `JOIN workflows` in every fuel/cost query IS the tenancy predicate — so
//! the rows were written and then joined away. Measured on the live database
//! 2026-09-03: a sub-workflow node climbed 91.3% → 95.2% → 96.5% → 99.2% of its
//! ceiling on four consecutive daily runs and then died of fuel exhaustion,
//! while the fuel report answered `at_risk: 0` and `high_utilisation_nodes: 0`
//! throughout and omitted the module entirely. 394 rollup rows fleet-wide
//! carried an unresolvable workflow id.
//!
//! The assertion below is deliberately three-way: the recorded id must be the
//! SUB-workflow's, not the synthetic execution id (the bug) and not the
//! PARENT's (the plausible wrong fix — it would merge two different node
//! populations under one name).

use std::sync::Arc;

use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_core::WasmModuleArtifact;
use talos_workflow_engine_test_utils::{
    capture::{CaptureNodeLifecycleHook, LifecycleCall},
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
async fn a_sub_workflow_node_is_attributed_to_the_sub_workflow() {
    let parent_wf_id = Uuid::new_v4();
    let sub_wf_id = Uuid::new_v4();
    let module_id = Uuid::new_v4();

    let sub_graph = WorkflowGraphBuilder::new()
        .add_module("recall", module_id, None)
        .build()
        .expect("sub graph builds");

    let hook = Arc::new(CaptureNodeLifecycleHook::new());

    let mut parent = minimal_engine();
    parent.set_user_id(Uuid::new_v4());
    // The parent has its OWN definition id, exactly as `build_engine` sets it
    // on every real top-level run. Without this the "inherits the parent"
    // failure mode would be indistinguishable from the fix.
    parent.set_workflow_id(parent_wf_id);
    parent.set_node_hook(hook.clone());
    parent.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new().with_module(module_id, stub_artifact(module_id)),
    ));
    parent.set_graph_store(Arc::new(
        InMemoryWorkflowGraphStore::new().with_graph(sub_wf_id, sub_graph),
    ));

    // A node output carrying `__fuel_consumed__` is what makes the controller
    // hook write a rollup row at all, so the payload is the realistic one.
    let dispatcher = Arc::new(ScriptedDispatcher::new().with_response(
        module_id,
        serde_json::json!({ "ok": true, "__fuel_consumed__": 991_930, "__fuel_limit__": 1_000_000 }),
    ));

    parent
        .execute_subworkflow_graph(sub_wf_id, serde_json::json!({}), dispatcher, None)
        .await
        .expect("the sub-workflow runs");

    let completed: Vec<_> = hook
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            LifecycleCall::Completed {
                workflow_id,
                execution_id,
                node_label,
                ..
            } => Some((workflow_id, execution_id, node_label)),
            _ => None,
        })
        .filter(|(_, _, label)| label.as_deref() == Some("recall"))
        .collect();

    assert_eq!(
        completed.len(),
        1,
        "the sub-workflow's module node must complete exactly once"
    );
    let (workflow_id, execution_id, _) = completed[0];
    assert_eq!(
        workflow_id, sub_wf_id,
        "a sub-workflow node's fuel must be attributed to the SUB-workflow"
    );
    assert_ne!(
        workflow_id, execution_id,
        "the synthetic per-run execution id must not be used as a workflow id — \
         no `workflows` row has it, so every tenancy join drops the record"
    );
    assert_ne!(
        workflow_id, parent_wf_id,
        "attributing the child's nodes to the PARENT would merge two different \
         node populations under one workflow name"
    );
}

/// The parent's own nodes are untouched by the fix.
///
/// `set_workflow_id` on the sub-engine must not reach back up: a top-level run
/// still attributes its nodes to the workflow the engine was built for.
#[tokio::test]
async fn the_parents_own_nodes_keep_the_parents_attribution() {
    let parent_wf_id = Uuid::new_v4();
    let sub_wf_id = Uuid::new_v4();
    let module_id = Uuid::new_v4();

    let graph = WorkflowGraphBuilder::new()
        .add_module("top", module_id, None)
        .build()
        .expect("graph builds");
    let sub_graph = WorkflowGraphBuilder::new()
        .add_module("inner", module_id, None)
        .build()
        .expect("sub graph builds");

    let hook = Arc::new(CaptureNodeLifecycleHook::new());
    let mut parent = minimal_engine();
    parent.set_user_id(Uuid::new_v4());
    parent.set_workflow_id(parent_wf_id);
    parent.set_node_hook(hook.clone());
    parent.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new().with_module(module_id, stub_artifact(module_id)),
    ));
    parent.set_graph_store(Arc::new(
        InMemoryWorkflowGraphStore::new().with_graph(sub_wf_id, sub_graph),
    ));
    parent
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load");

    let dispatcher = Arc::new(
        ScriptedDispatcher::new()
            .with_response(module_id, serde_json::json!({ "__fuel_consumed__": 10 })),
    );

    // Run the sub-workflow first, then the parent's own graph, through the same
    // engine and the same hook.
    parent
        .execute_subworkflow_graph(sub_wf_id, serde_json::json!({}), dispatcher.clone(), None)
        .await
        .expect("sub runs");
    parent
        .run_with_transport(dispatcher, None, Uuid::new_v4())
        .await
        .expect("parent runs");

    let mut seen: Vec<(String, Uuid)> = hook
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            LifecycleCall::Completed {
                workflow_id,
                node_label: Some(label),
                ..
            } => Some((label, workflow_id)),
            _ => None,
        })
        .collect();
    seen.sort();
    assert!(
        seen.contains(&("inner".to_string(), sub_wf_id)),
        "sub-workflow node must carry the sub-workflow id; saw {seen:?}"
    );
    assert!(
        seen.contains(&("top".to_string(), parent_wf_id)),
        "the parent's own node must still carry the parent id; saw {seen:?}"
    );
}

/// The chokepoint covers the OTHER two hydration sites too.
///
/// `execute_subworkflow_graph` is the site that was diagnosed, but
/// dynamic/capability dispatch (`scheduler_handlers`) and the agent-loop body
/// hydrate their own sub-engines through the same `into_engine_with_graph`.
/// Making `workflow_id` a required PARAMETER is what stops a repair of the
/// diagnosed site from converting a uniform bug into a per-dispatch-kind one —
/// those two paths cannot compile without supplying an id. What a type cannot
/// check is that the id supplied is the RIGHT one, so that half is pinned here:
/// each site must pass the id of the workflow whose graph it just loaded.
#[test]
fn every_hydration_site_passes_the_id_of_the_graph_it_loaded() {
    let src = include_str!("../src/scheduler_handlers.rs");
    assert!(
        src.contains("into_engine_with_graph(sub_wf_id, &graph_json)"),
        "dynamic/capability dispatch must attribute to its dispatch target"
    );
    assert!(
        src.contains("into_engine_with_graph(body_wf_id, &graph_json)"),
        "the agent-loop body must attribute to the body workflow"
    );
    let subflow = include_str!("../src/engine_dispatch_subflow.rs");
    assert!(
        subflow.contains("into_engine_with_graph(sub_wf_id, &graph_json)"),
        "sub-workflow dispatch must attribute to the sub-workflow"
    );
}
