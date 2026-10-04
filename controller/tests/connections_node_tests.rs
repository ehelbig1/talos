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
//! No worker is involved in the `connections` node: it runs in the
//! controller, so the dispatcher here is never called for it.
//!
//! The `for_each_connection` node is driven against the same real listing:
//! what the reader emits is what the engine's planner reads, a bank whose
//! credential the vault does not hold is skipped, and a second user's run
//! reads none of the owner's banks.
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

/// Stands in for the worker on a `for_each_connection` run: keeps each job
/// and answers with the bank it was configured for.
#[derive(Default)]
struct BankReader {
    jobs: std::sync::Mutex<Vec<DispatchJob>>,
}

#[async_trait]
impl NodeDispatcher for BankReader {
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError> {
        let bank = job.input_payload["INSTITUTION"].clone();
        self.jobs.lock().unwrap().push(job);
        Ok(DispatchResult {
            output: json!({ "bank": bank }),
        })
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

/// Run one module node fanned out over `plaid` as `user`, with the real
/// reader. Returns the node's result (or the run's error) and the jobs.
async fn run_for_each(
    pool: &Pool<Postgres>,
    secrets: &Arc<SecretsManager>,
    user: Uuid,
) -> (Result<Value, String>, Vec<DispatchJob>) {
    let module = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_raw_node(json!({
            "id": "banks",
            "type": module.to_string(),
            "kind": "for_each_connection",
            "data": { "for_each_connection": {
                "provider": "plaid",
                "bind": { "ACCESS_TOKEN": "vault_reference", "INSTITUTION": "account" },
            }},
        }))
        .build()
        .expect("graph builds");
    let mut engine = minimal_engine();
    engine.set_user_id(user);
    engine.set_module_fetcher(Arc::new(
        talos_workflow_engine_test_utils::memory::InMemoryModuleFetcher::new().with_module(
            module,
            talos_workflow_engine_core::WasmModuleArtifact {
                module_id: module,
                content_hash: "stub".into(),
                wasm_bytes: vec![],
                oci_url: None,
                max_fuel: 1_000_000,
                capability_world: "http-node".into(),
                allowed_hosts: vec![],
                allowed_methods: vec!["POST".into()],
                allowed_secrets: vec!["plaid/access_token/*".into()],
                requires_approval_for: vec![],
                integration_name: None,
                config: None,
            },
        ),
    ));
    engine.set_connections_reader(Arc::new(
        talos_engine::connections_reader::PostgresConnectionsReader::new(
            pool.clone(),
            secrets.clone(),
        ),
    ));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load graph");
    let node = *engine
        .node_labels()
        .iter()
        .find(|(_, label)| label.as_str() == "banks")
        .expect("node")
        .0;
    let dispatcher = Arc::new(BankReader::default());
    let result = engine
        .run_with_trigger_input_transport(dispatcher.clone(), None, json!({}), Uuid::new_v4())
        .await
        .map(|ctx| ctx.results.get(&node).cloned().expect("a result"))
        .map_err(|e| e.to_string());
    let jobs = dispatcher.jobs.lock().unwrap().clone();
    (result, jobs)
}

#[tokio::test]
async fn the_fan_out_reads_the_real_listing_for_the_running_user_only() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let secrets = ctx.secrets_manager.clone();
    secrets.initialize().await.expect("active DEK");
    let owner = create_test_user(&ctx.auth_service, "fanout_owner@example.com").await;
    let stranger = create_test_user(&ctx.auth_service, "fanout_stranger@example.com").await;
    connect_bank(&pool, owner, "item-made-up-5", "Fifth Example Bank").await;
    connect_bank(&pool, owner, "item-made-up-6", "Sixth Example Bank").await;
    // The vault holds the first bank's credential and not the second's.
    secrets
        .create_secret(
            "Plaid access token (Fifth Example Bank)",
            "plaid/access_token/item-made-up-5",
            "made-up-token-value",
            None,
            owner,
            vec![],
            None,
        )
        .await
        .expect("store a credential");

    let (result, jobs) = run_for_each(&pool, &secrets, owner).await;
    let out = result.expect("one bank was read");
    assert_eq!(out["connections"]["listed"], json!(2), "{out}");
    assert_eq!(out["connections"]["read"], json!(1), "{out}");
    assert_eq!(
        out["connections"]["skipped"],
        json!([{ "account": "Sixth Example Bank", "reason": "not_stored" }])
    );
    assert_eq!(jobs.len(), 1);
    assert_eq!(
        jobs[0].input_payload["ACCESS_TOKEN"],
        json!("vault://plaid/access_token/item-made-up-5")
    );
    assert_eq!(
        jobs[0].input_payload["INSTITUTION"],
        json!("Fifth Example Bank")
    );
    // A reference is a name; the value never enters a node's input or output.
    assert!(!jobs[0]
        .input_payload
        .to_string()
        .contains("made-up-token-value"));
    assert!(!out.to_string().contains("made-up-token-value"), "{out}");

    // The same graph as another user: nothing of the owner's is listed, run
    // or named.
    let (result, jobs) = run_for_each(&pool, &secrets, stranger).await;
    let other = result.expect("an empty read is not a failure");
    assert_eq!(other["connections"]["listed"], json!(0), "{other}");
    assert!(jobs.is_empty());
    assert!(!other.to_string().contains("Example Bank"), "{other}");
}
