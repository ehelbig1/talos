//! A failed run's completed nodes can be read back (2026-10-13).
//!
//! A run failed at its sixth node, and `get_node_output` for the five that
//! had completed answered "not found … available: [__trigger_input__]": a
//! failed run stored its trigger and nothing else.
//!
//! Driven here against real rows, through the real finalizer (redaction,
//! the size bound, encryption at rest) and the real handler (ownership, the
//! label lookup): what `failure_output` builds is what a caller reads back.
//! The engine's half (a failed run hands over its completed outputs) is
//! `talos-workflow-engine/tests/partial_results_on_failure.rs`; a run driven
//! through NATS is not available to this harness.
//!
//! `common` harness (a template clone per test), so the migrated-database
//! job runs it.

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use std::collections::HashMap;

use mcp_common::{agent, error_message, mcp_state, text_json};
use serde_json::{json, Value};
use uuid::Uuid;

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, created_at, updated_at) \
         VALUES ($1, $2, 'x', NOW(), NOW())",
    )
    .bind(id)
    .bind(format!("failed-run-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// A three-node workflow and one RUNNING execution of it.
async fn seed_running_execution(pool: &sqlx::PgPool, user_id: Uuid) -> Uuid {
    let wf_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, module_uri, graph_json, status, is_enabled) \
         VALUES ($1, $2, $3, 'test:failed-run', $4, 'active', true)",
    )
    .bind(wf_id)
    .bind(user_id)
    .bind(format!("failed-run-wf-{}", wf_id.simple()))
    .bind(
        json!({
            "nodes": [
                { "id": "n1", "type": "module", "data": { "label": "fetch" } },
                { "id": "n2", "type": "module", "data": { "label": "compose" } },
                { "id": "n3", "type": "module", "data": { "label": "send" } },
            ],
            "edges": [
                { "source": "n1", "target": "n2" },
                { "source": "n2", "target": "n3" },
            ],
        })
        .to_string(),
    )
    .execute(pool)
    .await
    .expect("seed workflow");
    // Every execution carries an actor.
    let actor_id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(actor_id)
        .bind(user_id)
        .bind(format!("failed-run-actor-{}", actor_id.simple()))
        .execute(pool)
        .await
        .expect("seed actor");
    let exec_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status, started_at) \
         VALUES ($1, $2, $3, $4, 'running', NOW())",
    )
    .bind(exec_id)
    .bind(wf_id)
    .bind(user_id)
    .bind(actor_id)
    .execute(pool)
    .await
    .expect("seed execution");
    exec_id
}

#[tokio::test]
async fn the_outputs_of_the_nodes_that_completed_can_be_read_back_from_a_failed_run() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let exec_id = seed_running_execution(&pool, owner).await;
    let state = mcp_state(pool.clone()).await;

    // What the engine kept of a run in which `fetch` and `compose` completed
    // and `send` failed, keyed as the engine keys it.
    let (n1, n2, trigger) = (
        talos_workflow_engine_core::engine_node_uuid("n1"),
        talos_workflow_engine_core::engine_node_uuid("n2"),
        Uuid::new_v4(),
    );
    let partial: HashMap<Uuid, Value> = [
        (trigger, json!({ "seed": true })),
        (
            n1,
            json!({ "items": [1, 2, 3], "echoed": "Bearer ghp_abcdefghijklmnopqrstuvwx12" }),
        ),
        (n2, json!({ "subject": "Three items" })),
    ]
    .into_iter()
    .collect();
    let labels: HashMap<Uuid, String> = [
        (trigger, "__trigger__".to_string()),
        (n1, "fetch".to_string()),
        (n2, "compose".to_string()),
    ]
    .into_iter()
    .collect();
    let stored = talos_execution_result_collector::failure_output(
        &labels,
        Some(partial),
        Some(&json!({ "ticket": "ABC-12" })),
    );
    state
        .workflow_repo
        .mark_execution_failed(exec_id, "node 'send' failed: refused", Some(&stored))
        .await
        .expect("finalize as failed");

    let status: String = sqlx::query_scalar("SELECT status FROM workflow_executions WHERE id = $1")
        .bind(exec_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "failed");

    let call = |node: &'static str, as_user: Uuid| {
        let state = &state;
        async move {
            controller::mcp::executions::dispatch(
                "get_node_output",
                Some(json!(1)),
                &json!({ "execution_id": exec_id.to_string(), "node_id": node }),
                state,
                agent(as_user),
            )
            .await
            .expect("get_node_output is dispatched")
        }
    };

    // By label and by graph id: the completed nodes' outputs.
    for node in ["compose", "n2"] {
        let body = text_json(&call(node, owner).await);
        assert!(
            body.to_string().contains("Three items"),
            "{node}: the completed node's output was not returned: {body}"
        );
    }
    let fetch = text_json(&call("fetch", owner).await).to_string();
    assert!(fetch.contains("items"), "{fetch}");
    assert!(
        !fetch.contains("ghp_abcdefghijklmnopqrstuvwx12"),
        "a completed node's output came back unredacted"
    );

    // The node that failed has none, and the reply says why.
    let msg = error_message(&call("send", owner).await);
    assert!(msg.contains("Nodes with a stored output: ["), "{msg}");
    assert!(msg.contains("fetch") && msg.contains("compose"), "{msg}");
    assert!(!msg.contains("__trigger_input__"), "{msg}");
    assert!(
        msg.contains("only the nodes that completed before the failure"),
        "{msg}"
    );

    // Another user is told the run does not exist, and learns nothing else.
    let denied = error_message(&call("compose", stranger).await);
    assert!(denied.contains("not found or access denied"), "{denied}");
    assert!(
        !denied.contains("Three items") && !denied.contains("compose"),
        "{denied}"
    );

    // A retry still finds the trigger where it always was.
    let found = state
        .execution_repo
        .lookup_execution(exec_id, owner)
        .await
        .expect("read the execution");
    let talos_execution_repository::ExecutionLookup::Live(row) = found else {
        panic!("the execution was just finalized and is in the live table");
    };
    assert_eq!(
        talos_execution_result_collector::extract_trigger_input(row.output_data.as_ref()),
        json!({ "ticket": "ABC-12" })
    );
}

/// The paths whose failure statement records only the error (the scheduler,
/// the webhook router, crash recovery, …) fail the row first and attach the
/// completed outputs after. Through whichever repository the path holds,
/// that second write:
///
/// * lands on a row that is `failed` and holds no output, sealed at rest,
///   and changes nothing else about the row;
/// * lands NOWHERE else: not on a row that completed, is still running or
///   was cancelled, and not over an output a failed row already holds.
#[tokio::test]
async fn completed_outputs_attach_only_to_a_failed_row_that_holds_none() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let state = mcp_state(pool.clone()).await;
    let outputs =
        json!({ "fetch": { "items": [1, 2, 3] }, "compose": { "subject": "Three items" } });
    let other = json!({ "fetch": { "items": ["something else"] } });

    // Built the way the production paths build them: a repository that holds
    // the secrets manager seals, one that does not writes redacted plaintext.
    let sm = state.secrets_manager.clone();
    sm.initialize().await.expect("an active encryption key");
    let sealing_workflows = talos_workflow_repository::WorkflowRepository::new(pool.clone())
        .with_encryption(sm.clone());
    let sealing_executions =
        talos_execution_repository::ExecutionRepository::with_encryption(pool.clone(), sm.clone());

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Via {
        WorkflowRepositorySealing,
        ExecutionRepositorySealing,
        WorkflowRepositoryPlain,
        ExecutionRepositoryPlain,
    }
    impl Via {
        fn seals(self) -> bool {
            matches!(
                self,
                Via::WorkflowRepositorySealing | Via::ExecutionRepositorySealing
            )
        }
    }
    let attach = |via: Via, exec_id: Uuid, value: Value| {
        let (state, sealing_workflows, sealing_executions) =
            (&state, &sealing_workflows, &sealing_executions);
        async move {
            match via {
                Via::WorkflowRepositorySealing => {
                    sealing_workflows
                        .attach_failed_run_outputs(exec_id, &value)
                        .await
                }
                Via::ExecutionRepositorySealing => {
                    sealing_executions
                        .attach_failed_run_outputs(exec_id, &value)
                        .await
                }
                Via::WorkflowRepositoryPlain => {
                    state
                        .workflow_repo
                        .attach_failed_run_outputs(exec_id, &value)
                        .await
                }
                Via::ExecutionRepositoryPlain => {
                    state
                        .execution_repo
                        .attach_failed_run_outputs(exec_id, &value)
                        .await
                }
            }
            .expect("attach")
        }
    };
    // (status, error, plaintext column empty, ciphertext present)
    let row = |exec_id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (String, Option<String>, bool, bool)>(
                "SELECT status, error_message, output_data IS NULL, output_data_enc IS NOT NULL \
                 FROM workflow_executions WHERE id = $1",
            )
            .bind(exec_id)
            .fetch_one(&pool)
            .await
            .expect("read row")
        }
    };
    // What a reader gets back, sealed or not.
    let stored = |exec_id: Uuid| {
        let sealing_executions = &sealing_executions;
        async move {
            let found = sealing_executions
                .lookup_execution(exec_id, owner)
                .await
                .expect("lookup");
            let talos_execution_repository::ExecutionLookup::Live(row) = found else {
                panic!("the execution is live");
            };
            row.output_data
        }
    };

    for via in [
        Via::WorkflowRepositorySealing,
        Via::ExecutionRepositorySealing,
        Via::WorkflowRepositoryPlain,
        Via::ExecutionRepositoryPlain,
    ] {
        // Failed the way a scheduled run is failed: the error, and no output.
        let failed = seed_running_execution(&pool, owner).await;
        talos_workflow_repository::fail_workflow_execution_unless_terminal(
            &pool,
            failed,
            "Scheduled workflow failed: node 'send' failed: refused",
        )
        .await
        .expect("fail the run");
        assert!(attach(via, failed, outputs.clone()).await, "{via:?}");
        let (status, error, plaintext_empty, sealed) = row(failed).await;
        assert_eq!(status, "failed", "{via:?}: attaching changed the outcome");
        assert_eq!(
            error.as_deref(),
            Some("Scheduled workflow failed: node 'send' failed: refused"),
            "{via:?}: attaching changed the recorded error"
        );
        if via.seals() {
            assert!(
                plaintext_empty && sealed,
                "{via:?}: the outputs were not sealed at rest"
            );
        } else {
            assert!(!plaintext_empty && !sealed, "{via:?}");
        }
        assert_eq!(stored(failed).await, Some(outputs.clone()), "{via:?}");

        // A row that already holds an output keeps it.
        assert!(!attach(via, failed, other.clone()).await, "{via:?}");
        assert_eq!(
            stored(failed).await,
            Some(outputs.clone()),
            "{via:?}: an output was replaced"
        );

        // Through the tool, for its owner (the harness's own repositories
        // do not hold the secrets manager, so the plaintext rows).
        if !via.seals() {
            let reply = controller::mcp::executions::dispatch(
                "get_node_output",
                Some(json!(1)),
                &json!({ "execution_id": failed.to_string(), "node_id": "compose" }),
                &state,
                agent(owner),
            )
            .await
            .expect("get_node_output is dispatched");
            assert!(
                text_json(&reply).to_string().contains("Three items"),
                "{via:?}"
            );
        }

        // Rows in any other state are not touched.
        for status in ["running", "completed", "cancelled", "waiting"] {
            let exec = seed_running_execution(&pool, owner).await;
            sqlx::query("UPDATE workflow_executions SET status = $2 WHERE id = $1")
                .bind(exec)
                .bind(status)
                .execute(&pool)
                .await
                .expect("set status");
            assert!(
                !attach(via, exec, outputs.clone()).await,
                "{via:?}: outputs were attached to a {status} row"
            );
            let (now, _, plaintext_empty, sealed) = row(exec).await;
            assert_eq!(now, status);
            assert!(
                plaintext_empty && !sealed,
                "{via:?}: a {status} row was written to"
            );
            assert_eq!(stored(exec).await, None, "{via:?}: {status}");
        }
    }
}

/// Answers `fetch` at once, never answers `compose`, and says when `compose`
/// has been asked: by then `fetch`'s output is committed.
struct StallsAtCompose {
    fetch: Uuid,
    compose_asked: std::sync::Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl talos_workflow_engine_core::NodeDispatcher for StallsAtCompose {
    async fn dispatch(
        &self,
        job: talos_workflow_engine_core::DispatchJob,
    ) -> Result<talos_workflow_engine_core::DispatchResult, talos_workflow_engine_core::BoxError>
    {
        if job.module_id == self.fetch {
            return Ok(talos_workflow_engine_core::DispatchResult {
                output: json!({ "items": [1, 2, 3], "echoed": "Bearer ghp_abcdefghijklmnopqrstuvwx12" }),
            });
        }
        self.compose_asked.notify_one();
        std::future::pending::<()>().await;
        unreachable!()
    }
}

/// A scheduled run that ran out of the scheduler's own budget stored its
/// error and nothing else: the timeout sat around the whole run function and
/// dropped the engine with it, so there was nothing left to read the
/// completed nodes from. The run is now stopped at its deadline with the
/// engine still there, and `finish_timed_out_run` is what the scheduler then
/// calls. Driven here over a real engine whose run was dropped that way.
#[tokio::test]
async fn a_scheduled_run_stopped_at_its_deadline_keeps_what_its_completed_nodes_produced() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let exec_id = seed_running_execution(&pool, owner).await;
    let state = mcp_state(pool.clone()).await;
    let sm = state.secrets_manager.clone();
    sm.initialize().await.expect("an active encryption key");

    let (fetch, compose) = (Uuid::new_v4(), Uuid::new_v4());
    let graph = talos_workflow_engine::WorkflowGraphBuilder::new()
        .add_module("fetch", fetch, None)
        .add_module("compose", compose, None)
        .edge("fetch", "compose")
        .build()
        .expect("graph builds");
    let artifact = |id: Uuid| talos_workflow_engine_core::WasmModuleArtifact {
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
    };
    let mut engine = talos_workflow_engine_test_utils::minimal_engine();
    engine.set_user_id(owner);
    engine.set_module_fetcher(std::sync::Arc::new(
        talos_workflow_engine_test_utils::memory::InMemoryModuleFetcher::new()
            .with_module(fetch, artifact(fetch))
            .with_module(compose, artifact(compose)),
    ));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load graph");

    // The scheduler's shape: the RUN is dropped at the deadline, the engine
    // is not. `fetch` has completed; `compose` is in flight and never answers.
    let compose_asked = std::sync::Arc::new(tokio::sync::Notify::new());
    let dispatcher = std::sync::Arc::new(StallsAtCompose {
        fetch,
        compose_asked: std::sync::Arc::clone(&compose_asked),
    });
    tokio::select! {
        biased;
        () = compose_asked.notified() => {}
        ended = engine.run_with_trigger_input_transport(dispatcher, None, json!({}), exec_id) => {
            panic!("`compose` never answers, so the run cannot end: {:?}", ended.map(|_| ()))
        }
    }

    // A live subscriber, as the dashboard's execution updates are.
    let (sender, mut events) = tokio::sync::broadcast::channel(8);
    let timed_out = talos_scheduler::TimedOutRun {
        execution_id: exec_id,
        workflow_id: Uuid::new_v4(),
        schedule_id: Uuid::new_v4(),
        timeout_secs: 3600,
        phase: talos_metrics::SCHEDULER_PHASE_STEADY,
    };
    talos_scheduler::finish_timed_out_run(&engine, &pool, &sm, &sender, timed_out).await;

    let (status, error, plaintext_empty, sealed) =
        sqlx::query_as::<_, (String, Option<String>, bool, bool)>(
            "SELECT status, error_message, output_data IS NULL, output_data_enc IS NOT NULL \
             FROM workflow_executions WHERE id = $1",
        )
        .bind(exec_id)
        .fetch_one(&pool)
        .await
        .expect("read row");
    assert_eq!(status, "failed");
    assert_eq!(
        error.as_deref(),
        Some("Execution timed out after 3600 seconds"),
        "the recorded reason is the timeout, unchanged by keeping the outputs"
    );
    assert!(
        plaintext_empty && sealed,
        "the completed outputs were not stored, or not sealed at rest"
    );

    let found =
        talos_execution_repository::ExecutionRepository::with_encryption(pool.clone(), sm.clone())
            .lookup_execution(exec_id, owner)
            .await
            .expect("lookup");
    let talos_execution_repository::ExecutionLookup::Live(row) = found else {
        panic!("the execution is live");
    };
    let stored = row
        .output_data
        .expect("a timed-out run's completed outputs");
    assert_eq!(stored["fetch"]["items"], json!([1, 2, 3]), "{stored}");
    assert!(
        stored.get("compose").is_none(),
        "the node that was still running has no output: {stored}"
    );
    assert!(
        !stored
            .to_string()
            .contains("ghp_abcdefghijklmnopqrstuvwx12"),
        "a completed node's output was stored unredacted"
    );

    // Taken once: the engine does not go on holding the run's outputs.
    assert!(engine.take_partial_results().is_none());

    // The subscriber was told, once, that the run failed and why. Neither
    // scheduler timeout used to say anything: a watcher of a scheduled run
    // that timed out saw its last node event and then nothing.
    let run_level: Vec<talos_engine::events::ExecutionEvent> =
        std::iter::from_fn(|| events.try_recv().ok())
            .filter(|event| event.node_id.is_none())
            .collect();
    assert_eq!(run_level.len(), 1, "{run_level:?}");
    assert_eq!(run_level[0].execution_id, exec_id);
    assert!(matches!(
        run_level[0].status,
        talos_engine::events::ExecutionStatus::Failed
    ));
    assert_eq!(
        run_level[0].log_message.as_deref(),
        Some("Execution timed out after 3600 seconds")
    );

    // The other timeout firing afterwards (the backstop, when the first
    // one's writes ran long) fails nothing and so announces nothing.
    talos_scheduler::finish_timed_out_run(&engine, &pool, &sm, &sender, timed_out).await;
    assert!(
        events.try_recv().is_err(),
        "a row that was already failed was announced a second time"
    );

    // A run an operator cancelled before the timeout fired stays cancelled,
    // and the subscriber is not told it failed.
    let cancelled = seed_running_execution(&pool, owner).await;
    sqlx::query("UPDATE workflow_executions SET status = 'cancelled' WHERE id = $1")
        .bind(cancelled)
        .execute(&pool)
        .await
        .expect("cancel");
    talos_scheduler::finish_timed_out_run(
        &engine,
        &pool,
        &sm,
        &sender,
        talos_scheduler::TimedOutRun {
            execution_id: cancelled,
            ..timed_out
        },
    )
    .await;
    let status: String = sqlx::query_scalar("SELECT status FROM workflow_executions WHERE id = $1")
        .bind(cancelled)
        .fetch_one(&pool)
        .await
        .expect("read");
    assert_eq!(status, "cancelled");
    assert!(
        events.try_recv().is_err(),
        "a cancelled run was announced as failed"
    );
}
