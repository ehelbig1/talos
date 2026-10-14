//! Every module of a run receives how the run was started, read from its own
//! row (2026-10-14).
//!
//! Each start route's row is written through the PRODUCTION insert that route
//! uses, with the provenance that route writes (as
//! `execution_started_by_tests` does), and then a real engine run reads it
//! through the real `PostgresStartedByResolver`, wired as the controller
//! builder wires it. The module's input is what is asserted: the kind the
//! listing shows, and nothing else (no link id, no channel id, no user id).
//!
//! Row security is left OFF in this binary (`TALOS_RLS_SET_ROLE=0`, read once
//! per process), so the resolver's own `user_id` predicate is what refuses a
//! run that is not the engine's user's.
//!
//! `common` harness (a template clone per test), so the migrated-database job
//! runs it.

mod common;

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use sqlx::{Pool, Postgres};
use talos_engine::started_by_resolver::PostgresStartedByResolver;
use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_core::{SystemNodeKind, WasmModuleArtifact};
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher,
    memory::{InMemoryModuleFetcher, InMemoryWorkflowGraphStore},
    minimal_engine,
};
use talos_workflow_repository::{
    ExecutionOrigin, ExecutionPriority, InitialExecutionStatus, WorkflowRepository,
};
use uuid::Uuid;

fn leave_row_security_unenforced() {
    std::env::set_var("TALOS_RLS_SET_ROLE", "0");
}

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'started-by')",
    )
    .bind(id)
    .bind(format!("started-by-inject-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_actor(pool: &Pool<Postgres>, user: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(id)
        .bind(user)
        .bind(format!("started-by-inject-actor-{id}"))
        .execute(pool)
        .await
        .expect("seed actor");
    id
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

struct World {
    pool: Pool<Postgres>,
    _db: common::TestDb,
    user: Uuid,
    actor: Uuid,
    workflow: Uuid,
    workflows: WorkflowRepository,
}

async fn world() -> World {
    leave_row_security_unenforced();
    let (pool, db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let actor = seed_actor(&pool, user).await;
    let workflow = common::create_test_workflow(&pool, user, "started-by-inject").await;
    World {
        workflows: WorkflowRepository::new(pool.clone()),
        pool,
        _db: db,
        user,
        actor,
        workflow,
    }
}

impl World {
    /// A row through the insert `trigger_workflow`, the scheduler, the
    /// webhook router and action links use.
    async fn through_the_trigger_insert(&self, provenance: &Value) -> Uuid {
        let id = Uuid::new_v4();
        self.workflows
            .create_execution_under_concurrency_limit(
                id,
                self.workflow,
                self.user,
                None,
                ExecutionPriority::Normal,
                Some(self.actor),
                Some(provenance),
                None,
                None,
                InitialExecutionStatus::Running,
                talos_workflow_repository::RunMode::Real,
            )
            .await
            .expect("insert");
        id
    }

    /// Run `up → assess (sub_workflow: reader)` as `engine_user` under
    /// `execution`, and return what `up` and the child's `reader` received
    /// as `__started_by__`.
    async fn run(&self, execution: Uuid, engine_user: Uuid) -> (Option<Value>, Option<Value>) {
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
        let mut engine = minimal_engine();
        engine.set_user_id(engine_user);
        engine.set_workflow_id(self.workflow);
        engine.set_started_by_resolver(Arc::new(PostgresStartedByResolver::new(self.pool.clone())));
        engine.set_module_fetcher(Arc::new(
            InMemoryModuleFetcher::new()
                .with_module(up, stub_artifact(up))
                .with_module(reader, stub_artifact(reader)),
        ));
        engine.set_graph_store(Arc::new(
            InMemoryWorkflowGraphStore::new().with_graph(child, child_graph),
        ));
        engine.set_execution_timeout(Some(Duration::from_secs(30)));
        engine
            .load_graph_from_json(&parent.to_string())
            .await
            .expect("loads");
        let dispatcher = Arc::new(
            ScriptedDispatcher::new()
                .with_response(up, json!({ "ok": 1 }))
                .with_response(reader, json!({ "ok": 2 })),
        );
        engine
            .run_with_trigger_input_transport(dispatcher.clone(), None, json!({}), execution)
            .await
            .expect("runs");
        let of = |m: Uuid| {
            dispatcher
                .jobs()
                .into_iter()
                .find(|j| j.module_id == m)
                .and_then(|j| j.input_payload.get("__started_by__").cloned())
        };
        (of(up), of(reader))
    }
}

/// Action link, manual trigger, schedule, webhook and `test_workflow`: each
/// row's kind reaches the run's own module and the child run's module, and
/// nothing but the kind does.
#[tokio::test]
async fn each_start_route_reaches_every_module_as_its_kind() {
    let w = world().await;
    let link = Uuid::new_v4();
    let schedule = Uuid::new_v4();
    let trigger = Uuid::new_v4();
    let mut routes: Vec<(&str, Uuid)> = vec![
        (
            "action_link",
            w.through_the_trigger_insert(
                &ExecutionOrigin::ActionLink { link_id: link }.stamp(None),
            )
            .await,
        ),
        (
            "manual",
            w.through_the_trigger_insert(&ExecutionOrigin::Manual.stamp(None))
                .await,
        ),
        (
            "schedule",
            w.through_the_trigger_insert(
                &json!({ "trigger_type": "scheduled", "schedule_id": schedule }),
            )
            .await,
        ),
        (
            "webhook",
            w.through_the_trigger_insert(
                &json!({ "trigger_type": "webhook", "trigger_id": trigger }),
            )
            .await,
        ),
    ];
    let test_run = Uuid::new_v4();
    let admission = w
        .workflows
        .create_test_execution(
            test_run,
            w.workflow,
            w.user,
            None,
            ExecutionPriority::Normal,
            Some(w.actor),
            talos_workflow_repository::RunMode::Real,
        )
        .await
        .expect("test insert");
    assert!(
        format!("{admission:?}").starts_with("Admitted"),
        "the test insert was refused: {admission:?}"
    );
    routes.push(("test", test_run));

    for (kind, execution) in routes {
        let (own, child) = w.run(execution, w.user).await;
        assert_eq!(
            own,
            Some(json!({ "kind": kind })),
            "{kind}: the run's module"
        );
        assert_eq!(
            child,
            Some(json!({ "kind": kind })),
            "{kind}: the child run's module"
        );
        let said = own.unwrap().to_string();
        for id in [link, schedule, trigger, w.user, w.actor] {
            assert!(
                !said.contains(&id.to_string()),
                "{kind}: an id leaked: {said}"
            );
        }
    }
}

/// An engine whose user does not own the execution reads nothing, and no
/// module gets a kind.
///
/// MUTATION that turns it red: drop `AND user_id = $2` from
/// `WorkflowRepository::started_by_of_execution`.
#[tokio::test]
async fn another_users_row_gives_no_kind() {
    let w = world().await;
    let stranger = seed_user(&w.pool).await;
    let execution = w
        .through_the_trigger_insert(&ExecutionOrigin::Manual.stamp(None))
        .await;
    let (own, child) = w.run(execution, stranger).await;
    assert_eq!(own, None);
    assert_eq!(child, None);
}
