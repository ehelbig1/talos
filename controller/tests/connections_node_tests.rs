//! The `connections` system node: a workflow reads which services its owner
//! has connected (2026-10-04).
//!
//! Driven in a real engine, with the real reader, against a real database:
//! * the owner's connected bank is listed with the reference its credential
//!   is stored at, and whether the vault holds it;
//! * a different user running the same graph is told about none of it;
//! * the provider filter keeps one service;
//! * with no reader wired, or no tenant identity, the node degrades instead
//!   of failing the run.
//!
//! No worker is involved: the node runs in the controller, so the dispatcher
//! here is never called for it.
//!
//! `common` harness (a template clone per test), so the migrated-database
//! job runs it.

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;

use async_trait::async_trait;
use common::{create_test_user, setup_test_context};
use serde_json::{json, Value};
use sqlx::{Pool, Postgres};
use talos_secrets_manager::SecretsManager;
use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_core::{
    BoxError, ChainDispatchRequest, ChainDispatchResult, DispatchJob, DispatchResult,
    NodeDispatcher, StepStatus, SystemNodeKind,
};
use talos_workflow_engine_test_utils::minimal_engine;
use uuid::Uuid;

/// A graph of one controller-side node dispatches nothing to a worker.
struct NeverDispatched;

#[async_trait]
impl NodeDispatcher for NeverDispatched {
    async fn dispatch(&self, _job: DispatchJob) -> Result<DispatchResult, BoxError> {
        Err("the connections node must not reach a worker".into())
    }

    async fn dispatch_chain(
        &self,
        _request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        Ok(ChainDispatchResult {
            steps: vec![],
            final_output: Value::Null,
            overall_status: StepStatus::Failed,
        })
    }
}

enum Reader {
    Wired(Pool<Postgres>, Arc<SecretsManager>),
    Absent,
}

/// Run a one-node graph as `user` and return the node's output.
async fn run_connections_node(reader: Reader, user: Option<Uuid>, provider: Option<&str>) -> Value {
    let graph = WorkflowGraphBuilder::new()
        .add_system_node(
            "conns",
            SystemNodeKind::Connections {
                provider: provider.map(str::to_string),
            },
        )
        .build()
        .expect("graph builds");

    let mut engine = minimal_engine();
    if let Some(user) = user {
        engine.set_user_id(user);
    }
    if let Reader::Wired(pool, secrets) = reader {
        engine.set_connections_reader(Arc::new(
            talos_engine::connections_reader::PostgresConnectionsReader::new(pool, secrets),
        ));
    }
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load graph");
    let node = engine
        .node_labels()
        .iter()
        .find(|(_, label)| label.as_str() == "conns")
        .map(|(id, _)| *id)
        .expect("the node is in the graph");

    let ctx = engine
        .run_with_trigger_input_transport(
            Arc::new(NeverDispatched),
            None,
            json!({}),
            Uuid::new_v4(),
        )
        .await
        .expect("run succeeds");
    ctx.results
        .get(&node)
        .cloned()
        .expect("the node produced a result")
}

async fn connect_bank(pool: &Pool<Postgres>, user: Uuid, item: &str, name: &str) {
    sqlx::query(
        "INSERT INTO plaid_items (user_id, item_id, institution_name, environment) \
         VALUES ($1, $2, $3, 'production')",
    )
    .bind(user)
    .bind(item)
    .bind(name)
    .execute(pool)
    .await
    .expect("seed a bank connection");
}

#[tokio::test]
async fn the_owner_is_told_their_connections_and_another_user_is_told_none() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let secrets = ctx.secrets_manager.clone();
    let owner = create_test_user(&ctx.auth_service, "connections_owner@example.com").await;
    let stranger = create_test_user(&ctx.auth_service, "connections_stranger@example.com").await;
    connect_bank(&pool, owner, "item-made-up-1", "First Example Bank").await;
    connect_bank(&pool, owner, "item-made-up-2", "Second Example Bank").await;

    let out = run_connections_node(
        Reader::Wired(pool.clone(), secrets.clone()),
        Some(owner),
        None,
    )
    .await;
    assert_eq!(out["available"], json!(true), "{out}");
    assert_eq!(out["count"], json!(2), "{out}");
    assert_eq!(out["truncated"], json!(false));
    assert_eq!(out["stored_checked"], json!(true));
    let first = &out["connections"][0];
    assert_eq!(first["service"], json!("plaid"));
    assert_eq!(first["account"], json!("First Example Bank"));
    assert_eq!(
        first["vault_reference"],
        json!("vault://plaid/access_token/item-made-up-1")
    );
    // Nothing was stored in the vault for this row, and the node says so
    // rather than implying the reference will resolve.
    assert_eq!(first["stored"], json!(false), "{first}");
    // The output names where a credential is; it carries none.
    let rendered = out.to_string();
    assert!(!rendered.contains("access-"), "{rendered}");

    // The same graph, run as someone else: none of the owner's rows.
    let other = run_connections_node(
        Reader::Wired(pool.clone(), secrets.clone()),
        Some(stranger),
        None,
    )
    .await;
    assert_eq!(other["available"], json!(true), "{other}");
    assert_eq!(other["count"], json!(0), "{other}");
    assert_eq!(other["connections"], json!([]));
    assert!(!other.to_string().contains("item-made-up"), "{other}");
}

#[tokio::test]
async fn the_provider_filter_keeps_one_service() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let secrets = ctx.secrets_manager.clone();
    let owner = create_test_user(&ctx.auth_service, "connections_filter@example.com").await;
    connect_bank(&pool, owner, "item-made-up-3", "Third Example Bank").await;

    let banks = run_connections_node(
        Reader::Wired(pool.clone(), secrets.clone()),
        Some(owner),
        Some("plaid"),
    )
    .await;
    assert_eq!(banks["count"], json!(1), "{banks}");
    assert_eq!(banks["provider"], json!("plaid"));

    let mail = run_connections_node(Reader::Wired(pool, secrets), Some(owner), Some("gmail")).await;
    assert_eq!(mail["available"], json!(true), "{mail}");
    assert_eq!(mail["count"], json!(0), "{mail}");
    assert_eq!(mail["provider"], json!("gmail"));
}

#[tokio::test]
async fn the_node_degrades_without_a_reader_or_an_identity() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let secrets = ctx.secrets_manager.clone();
    let owner = create_test_user(&ctx.auth_service, "connections_degrade@example.com").await;
    connect_bank(&pool, owner, "item-made-up-4", "Fourth Example Bank").await;

    let no_reader = run_connections_node(Reader::Absent, Some(owner), None).await;
    assert_eq!(no_reader["available"], json!(false), "{no_reader}");
    assert!(no_reader.get("connections").is_none(), "{no_reader}");

    // No resolved identity is no tenant: nothing is read, for anyone.
    let no_identity = run_connections_node(Reader::Wired(pool, secrets), None, None).await;
    assert_eq!(no_identity["available"], json!(false), "{no_identity}");
    assert!(
        !no_identity.to_string().contains("item-made-up"),
        "{no_identity}"
    );
}
