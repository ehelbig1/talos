//! One root run starts a bounded number of child runs (security review
//! 2026-10-14, G-2).
//!
//! The depth guard bounds a chain of sub-workflows; it does not bound the
//! TREE. A workflow whose only node is an `ensemble` of its own workflow
//! starts `count` children per level, every level, until the depth guard
//! fires — `count^depth` runs. The child-run budget is one counter per root
//! run, shared by every sub-engine at every depth, and taken at the one
//! place every sub-workflow handler hydrates a child engine.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_core::{BoxError, GraphLookup, SystemNodeKind, WorkflowGraphStore};
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher, memory::InMemoryModuleFetcher, minimal_engine,
};
use uuid::Uuid;

/// Returns the same graph for every id, and counts the child graphs asked for.
struct SelfStore {
    graph: serde_json::Value,
    reads: AtomicUsize,
}

#[async_trait]
impl WorkflowGraphStore for SelfStore {
    async fn get_graph(&self, _id: Uuid, _user: Uuid) -> Result<GraphLookup, BoxError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(GraphLookup::Found(self.graph.clone()))
    }
    async fn get_graphs(
        &self,
        ids: &[Uuid],
        _user: Uuid,
    ) -> Result<HashMap<Uuid, serde_json::Value>, BoxError> {
        Ok(ids.iter().map(|&id| (id, self.graph.clone())).collect())
    }
}

#[tokio::test]
async fn a_self_referencing_ensemble_stops_at_the_child_run_budget_not_at_the_depth_guard() {
    let wf = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_system_node(
            "fan_out",
            SystemNodeKind::Ensemble {
                child_workflow_id: wf,
                count: 3,
                consensus: "majority".into(),
                judge_workflow_id: None,
                timeout_secs: 30,
            },
        )
        .build()
        .unwrap();
    let store = Arc::new(SelfStore {
        graph: graph.clone(),
        reads: AtomicUsize::new(0),
    });

    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(InMemoryModuleFetcher::new()));
    engine.set_graph_store(store.clone());
    // Six levels of three is 3 + 9 + … + 729 = 1 092 child runs before the
    // depth guard would refuse. The budget stops the tree at 30.
    engine.set_max_subflow_depth(6);
    engine.set_max_child_runs(30);
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load");

    let started = std::time::Instant::now();
    let _ = engine
        .run_with_transport(Arc::new(ScriptedDispatcher::new()), None, Uuid::new_v4())
        .await;
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "the run must end at the budget"
    );

    // Every one of the 30 units was spent, by children at every depth…
    assert_eq!(engine.child_run_budget().remaining(), 0);
    // …and the tree stopped near there: once the budget is spent, each
    // ensemble's remaining siblings are refused without recursing, so at
    // most `count` reads follow each of the 30 hydrated children.
    let reads = store.reads.load(Ordering::SeqCst);
    assert!(
        reads <= 30 * 3 + 3,
        "the tree kept growing past its budget: {reads} child graphs read"
    );
}

#[test]
fn a_root_engine_has_the_documented_default_budget() {
    let engine = talos_workflow_engine::ParallelWorkflowEngine::new();
    assert_eq!(
        engine.child_run_budget().limit(),
        talos_workflow_engine::child_run_budget::DEFAULT_MAX_CHILD_RUNS_PER_RUN
    );
}

#[test]
fn a_sub_engine_spends_its_roots_budget_not_a_fresh_one() {
    let mut root = talos_workflow_engine::ParallelWorkflowEngine::new();
    root.set_max_child_runs(2);
    let graph = WorkflowGraphBuilder::new()
        .add_module("only", Uuid::new_v4(), None)
        .build()
        .unwrap();
    let child = root
        .adapter_set()
        .into_engine_with_graph(Uuid::new_v4(), &graph)
        .expect("first child");
    let _grandchild = child
        .adapter_set()
        .into_engine_with_graph(Uuid::new_v4(), &graph)
        .expect("second child, one level down, same budget");
    match root
        .adapter_set()
        .into_engine_with_graph(Uuid::new_v4(), &graph)
    {
        Err(talos_workflow_engine::WorkflowEngineError::ChildRunBudgetExhausted { limit }) => {
            assert_eq!(limit, 2)
        }
        Err(other) => panic!("expected the budget refusal, got {other:?}"),
        Ok(_) => panic!("a third child must be refused"),
    }
}

/// Records the actors it is asked about and refuses every child run.
struct RefuseAll {
    asked: std::sync::Mutex<Vec<Uuid>>,
}

#[async_trait]
impl talos_workflow_engine_core::ChildRunAdmission for RefuseAll {
    async fn admit_child_run(&self, actor_id: Uuid) -> Result<(), String> {
        self.asked.lock().unwrap().push(actor_id);
        Err("the actor's fuel cap is spent".into())
    }
}

/// A child run is asked about the actor it runs as, and a refusal stops it
/// (security review 2026-10-14, G-8): no child graph is run, and the parent
/// node carries the refusal.
#[tokio::test]
async fn a_child_run_refused_by_admission_does_not_run() {
    let child = Uuid::new_v4();
    let parent_graph = WorkflowGraphBuilder::new()
        .add_system_node(
            "call",
            SystemNodeKind::SubWorkflow {
                workflow_id: child,
                timeout_secs: 30,
            },
        )
        .build()
        .unwrap();
    let child_graph = WorkflowGraphBuilder::new()
        .add_module("child_module", Uuid::new_v4(), None)
        .build()
        .unwrap();
    let store = Arc::new(SelfStore {
        graph: child_graph,
        reads: AtomicUsize::new(0),
    });
    let admission = Arc::new(RefuseAll {
        asked: std::sync::Mutex::new(Vec::new()),
    });
    let actor = Uuid::new_v4();
    // The builder's `with_actor_id` is the sanctioned way to bind an actor
    // in the engine crate (check 29); the adapters are `minimal_engine`'s.
    let mut engine = talos_workflow_engine::ParallelWorkflowEngine::builder()
        .with_actor_id(actor)
        .with_user_id(Uuid::new_v4())
        .with_secrets_resolver(Arc::new(
            talos_workflow_engine_test_utils::memory::InMemorySecretsResolver::new(),
        ))
        .with_module_fetcher(Arc::new(InMemoryModuleFetcher::new()))
        .with_graph_store(store)
        .with_sandbox_root(None)
        .build();
    engine.set_child_run_admission(admission.clone());
    engine
        .load_graph_from_json(&serde_json::to_string(&parent_graph).unwrap())
        .await
        .expect("load");
    let dispatcher = Arc::new(ScriptedDispatcher::new());
    let result = engine
        .run_with_transport(dispatcher.clone(), None, Uuid::new_v4())
        .await;

    assert_eq!(
        *admission.asked.lock().unwrap(),
        vec![actor],
        "asked once, about the actor the child runs as"
    );
    assert!(dispatcher.jobs().is_empty(), "the child's module never ran");
    let err = match result {
        Ok(_) => panic!("a refused child must fail its parent node"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("not started"), "{err}");
}
