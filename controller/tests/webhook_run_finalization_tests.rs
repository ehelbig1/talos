//! A webhook-started workflow run reaches a terminal status (2026-10-13).
//!
//! The webhook router creates its execution row as `queued` and never moved
//! it to `running`. The success finalizers accept only a `running` (or
//! `resuming`) row, so a successful webhook run was never recorded as
//! completed: the row stayed `queued`. In the default (asynchronous) mode
//! the router did not finalize at all.
//!
//! Driven here on real rows: the statements the router's run now rests on,
//! and `record_async_run` (what the asynchronous mode does when its run
//! returns) over a real engine run. The router's own dispatch needs NATS,
//! which this harness has none of.
//!
//! `common` harness (a template clone per test), so the migrated-database
//! job runs it.

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use common::{create_test_user, create_test_workflow, setup_test_context};
use serde_json::json;
use talos_workflow_repository::{
    ConcurrencyAdmission, ExecutionPriority, InitialExecutionStatus, RunMode, WorkflowRepository,
};
use uuid::Uuid;

async fn status(pool: &sqlx::PgPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM workflow_executions WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read status")
}

/// Create a row exactly as the webhook router does: `queued`.
async fn queued_row(repo: &WorkflowRepository, workflow: Uuid, user: Uuid, actor: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let admission = repo
        .create_execution_under_concurrency_limit(
            id,
            workflow,
            user,
            None,
            ExecutionPriority::Normal,
            Some(actor),
            None,
            None,
            None,
            InitialExecutionStatus::Queued,
            RunMode::Real,
        )
        .await
        .expect("create");
    assert!(matches!(admission, ConcurrencyAdmission::Created));
    id
}

/// The defect, at the statement: a run that finished is not recorded as
/// completed while its row is still `queued`.
#[tokio::test]
async fn a_queued_row_is_not_completed_until_it_has_been_claimed_as_running() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "webhook-finalize@example.com").await;
    let workflow = create_test_workflow(&pool, user, "webhook-finalize").await;
    let actor = talos_actor_repository::ActorRepository::new(pool.clone())
        .get_or_create_default_actor(user)
        .await
        .expect("default actor");
    let repo = WorkflowRepository::new(pool.clone());
    let output = json!({ "send": { "sent": true } });

    // What the router did: run, then finalize, with the row never claimed.
    let unclaimed = queued_row(&repo, workflow, user, actor).await;
    repo.mark_execution_completed(unclaimed, &output)
        .await
        .expect("the finalizer runs");
    assert_eq!(
        status(&pool, unclaimed).await,
        "queued",
        "the success finalizer does not take a queued row: this is why an unclaimed \
         webhook run was never recorded as completed"
    );

    // What it does now: claim the row as running first, then finalize.
    let claimed = queued_row(&repo, workflow, user, actor).await;
    assert!(repo
        .mark_execution_running_from_queued(claimed)
        .await
        .expect("claim"));
    assert_eq!(status(&pool, claimed).await, "running");
    repo.mark_execution_completed(claimed, &output)
        .await
        .expect("finalize");
    assert_eq!(status(&pool, claimed).await, "completed");

    // A row an operator cancelled while it was queued is NOT claimable, so
    // the router does not run it.
    let cancelled = queued_row(&repo, workflow, user, actor).await;
    sqlx::query("UPDATE workflow_executions SET status = 'cancelled' WHERE id = $1")
        .bind(cancelled)
        .execute(&pool)
        .await
        .expect("cancel");
    assert!(!repo
        .mark_execution_running_from_queued(cancelled)
        .await
        .expect("claim"));
    assert_eq!(status(&pool, cancelled).await, "cancelled");
}

mod recording {
    use std::sync::Arc;

    use serde_json::json;
    use talos_webhooks::{record_async_run, AsyncRunRecord};
    use talos_workflow_engine::{
        ParallelWorkflowEngine, WorkflowEngineError, WorkflowGraphBuilder,
    };
    use talos_workflow_engine_core::{WasmModuleArtifact, WorkflowContext};
    use talos_workflow_engine_test_utils::{
        dispatch::ScriptedDispatcher, memory::InMemoryModuleFetcher, minimal_engine,
    };
    use talos_workflow_repository::WorkflowRepository;
    use uuid::Uuid;

    use super::{create_test_user, create_test_workflow, queued_row, setup_test_context, status};

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

    /// `fetch → send`, run as `execution_id`; `send` fails when `fails`.
    async fn run(
        execution_id: Uuid,
        fails: bool,
    ) -> (
        ParallelWorkflowEngine,
        Result<WorkflowContext, WorkflowEngineError>,
    ) {
        let (fetch, send) = (Uuid::new_v4(), Uuid::new_v4());
        let graph = WorkflowGraphBuilder::new()
            .add_module("fetch", fetch, None)
            .add_module("send", send, None)
            .edge("fetch", "send")
            .build()
            .expect("graph builds");
        let mut engine = minimal_engine();
        engine.set_user_id(Uuid::new_v4());
        engine.set_module_fetcher(Arc::new(
            InMemoryModuleFetcher::new()
                .with_module(fetch, stub_artifact(fetch))
                .with_module(send, stub_artifact(send)),
        ));
        engine
            .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
            .await
            .expect("load graph");
        let dispatcher = ScriptedDispatcher::new().with_response(
            fetch,
            json!({ "items": [1, 2], "echoed": "Bearer ghp_abcdefghijklmnopqrstuvwx12" }),
        );
        let dispatcher = if fails {
            dispatcher.with_error(send, "refused: token ghp_abcdefghijklmnopqrstuvwx12")
        } else {
            dispatcher.with_response(send, json!({ "sent": true }))
        };
        let outcome = engine
            .run_with_trigger_input_transport(Arc::new(dispatcher), None, json!({}), execution_id)
            .await;
        (engine, outcome)
    }

    /// What the asynchronous mode's task does when its run returns, on a row
    /// claimed as the router claims it.
    #[tokio::test]
    async fn an_async_webhook_run_is_recorded_whichever_way_it_ends() {
        let ctx = setup_test_context().await;
        let pool = ctx.db_pool.clone();
        let user = create_test_user(&ctx.auth_service, "webhook-record@example.com").await;
        let workflow = create_test_workflow(&pool, user, "webhook-record").await;
        let actor = talos_actor_repository::ActorRepository::new(pool.clone())
            .get_or_create_default_actor(user)
            .await
            .expect("default actor");
        // A repository that SEALS, as the router's does. It matters for what
        // this test is about: the sealing branch stores exactly what it is
        // handed, so redaction is the recorder's job there. (A repository
        // with no secrets manager redacts its plaintext itself, and would
        // hide a recorder that forgot to.)
        let sm = crate::mcp_common::mcp_state(pool.clone())
            .await
            .secrets_manager
            .clone();
        sm.initialize().await.expect("an active encryption key");
        let repo = WorkflowRepository::new(pool.clone()).with_encryption(sm.clone());
        let reader =
            talos_execution_repository::ExecutionRepository::with_encryption(pool.clone(), sm);
        let claimed = || async {
            let id = queued_row(&repo, workflow, user, actor).await;
            assert!(repo
                .mark_execution_running_from_queued(id)
                .await
                .expect("claim"));
            id
        };
        // (output as a reader gets it back, error, sealed at rest)
        let stored = |id: Uuid| {
            let (pool, reader) = (pool.clone(), &reader);
            async move {
                let sealed: bool = sqlx::query_scalar(
                    "SELECT output_data IS NULL AND output_data_enc IS NOT NULL \
                     FROM workflow_executions WHERE id = $1",
                )
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("read row");
                let found = reader.lookup_execution(id, user).await.expect("lookup");
                let talos_execution_repository::ExecutionLookup::Live(row) = found else {
                    panic!("the execution is live");
                };
                (row.output_data, row.error_message, sealed)
            }
        };
        const SECRET: &str = "ghp_abcdefghijklmnopqrstuvwx12";

        // It finished: completed, with its output, redacted.
        let id = claimed().await;
        let (engine, outcome) = run(id, false).await;
        let record = record_async_run(&engine, &repo, &pool, id, workflow, outcome).await;
        assert_eq!(record, AsyncRunRecord::Completed);
        assert_eq!(status(&pool, id).await, "completed");
        let (output, error, sealed) = stored(id).await;
        assert!(sealed, "a webhook run's output was not sealed at rest");
        let output = output.expect("a completed run stores its output");
        assert_eq!(output["send"]["sent"], true, "{output}");
        assert_eq!(output["fetch"]["items"], json!([1, 2]));
        assert!(error.is_none());
        assert!(
            !output.to_string().contains(SECRET),
            "a webhook run's output was stored unredacted"
        );

        // It failed: failed, with its error redacted, and what the node that
        // completed had produced.
        let id = claimed().await;
        let (engine, outcome) = run(id, true).await;
        let record = record_async_run(&engine, &repo, &pool, id, workflow, outcome).await;
        assert_eq!(record, AsyncRunRecord::Failed);
        assert_eq!(status(&pool, id).await, "failed");
        let (output, error, sealed) = stored(id).await;
        assert!(
            sealed,
            "a failed webhook run's kept outputs were not sealed"
        );
        let error = error.expect("a failed run stores its error");
        assert!(error.contains("send"), "{error}");
        assert!(!error.contains(SECRET), "the error was stored unredacted");
        let output = output.expect("the completed node's output is kept");
        assert_eq!(output["fetch"]["items"], json!([1, 2]), "{output}");
        assert!(output.get("send").is_none());
        assert!(!output.to_string().contains(SECRET));

        // An operator cancelled it, or another controller took it over: the
        // row is not this task's to write.
        for (stop, expected) in [
            (
                WorkflowEngineError::CancelledByOperator,
                AsyncRunRecord::LeftCancelled,
            ),
            (
                WorkflowEngineError::Cancelled,
                AsyncRunRecord::LeftToNewOwner,
            ),
        ] {
            let id = claimed().await;
            let (engine, _) = run(Uuid::new_v4(), false).await;
            let record = record_async_run(&engine, &repo, &pool, id, workflow, Err(stop)).await;
            assert_eq!(record, expected);
            assert_eq!(
                status(&pool, id).await,
                "running",
                "{expected:?}: a row that is not this task's was written to"
            );
            let (output, error, _) = stored(id).await;
            assert!(output.is_none() && error.is_none());
        }
    }
}
