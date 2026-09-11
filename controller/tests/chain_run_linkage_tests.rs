//! A workflow-chain run records WHICH module execution fired it on its OWN row,
//! and `module_executions.workflow_execution_id` is WRITE-ONCE.
//!
//! Until 2026-09-11 `talos_engine::workflow_chains` linked the two by
//! `UPDATE module_executions SET workflow_execution_id = <chain run>`. That
//! column is half of the WORM ledger's genesis key: the worker seals a job's
//! audit chain under `genesis(workflow_execution_id, job_id)` from the ids ON
//! THE WIRE, and a standalone (module-bound webhook / push) dispatch is signed
//! with `workflow_execution_id = job_id`. Rewriting the row after the seal made
//! the verifier expect a genesis the worker never wrote, so every module-bound
//! dispatch that fired a chain verified as `genesis_mismatch` — "possible
//! tampering" — on `TalosAuditVerificationFailures`. Measured on the reference
//! fleet: 3 of 3 such rows in the 30-day window, every post-partition chain
//! failure the sweep had reported.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use common::{create_test_user, create_test_workflow, setup_test_context};
use sqlx::Row;
use talos_audit_ledger::population::partition_sweep_rows;
use uuid::Uuid;

#[tokio::test]
async fn a_chain_run_links_to_its_trigger_without_moving_the_ledger_key() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "chain_link@example.com").await;
    let wf = create_test_workflow(&pool, user, "chain-link-target").await;
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, 'chain-link-actor')")
        .bind(actor)
        .bind(user)
        .execute(&pool)
        .await
        .expect("seed actor");
    let module_id = Uuid::new_v4();
    sqlx::query("INSERT INTO modules (id, user_id, name, kind) VALUES ($1, $2, 'chain-link-module', 'sandbox')")
        .bind(module_id)
        .bind(user)
        .execute(&pool)
        .await
        .expect("seed module");

    // A STANDALONE module execution: a module-bound webhook delivery, no
    // workflow execution — exactly the row `insert_webhook_module_execution`
    // writes (`workflow_execution_id` NULL), and the shape whose ledger the
    // worker sealed under `genesis(job_id, job_id)`.
    let trigger = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO module_executions \
             (id, module_id, user_id, status, trigger_type, started_at, completed_at, actor_id, payload_format) \
         VALUES ($1, $2, $3, 'completed', 'webhook', NOW(), NOW(), $4, 0)",
    )
    .bind(trigger)
    .bind(module_id)
    .bind(user)
    .bind(actor)
    .execute(&pool)
    .await
    .expect("seed standalone module execution");

    // The chain runner's row creation, driven directly.
    let run = Uuid::new_v4();
    talos_engine::workflow_chains::insert_chain_execution_row(
        &pool,
        run,
        wf,
        user,
        Some(actor),
        trigger,
    )
    .await
    .expect("chain run row");

    // The link lives on the RUN row …
    let row = sqlx::query(
        "SELECT status, actor_id, triggered_by_module_execution_id FROM workflow_executions WHERE id = $1",
    )
    .bind(run)
    .fetch_one(&pool)
    .await
    .expect("read chain run row");
    assert_eq!(row.try_get::<String, _>("status").unwrap(), "running");
    assert_eq!(
        row.try_get::<Option<Uuid>, _>("actor_id").unwrap(),
        Some(actor)
    );
    assert_eq!(
        row.try_get::<Option<Uuid>, _>("triggered_by_module_execution_id")
            .unwrap(),
        Some(trigger),
        "the chain run names the module execution that fired it"
    );

    // … and the MODULE row's ledger key is untouched: still NULL, as dispatched.
    let still_null: Option<Uuid> =
        sqlx::query_scalar("SELECT workflow_execution_id FROM module_executions WHERE id = $1")
            .bind(trigger)
            .fetch_one(&pool)
            .await
            .expect("read trigger row");
    assert_eq!(
        still_null, None,
        "module_executions.workflow_execution_id is WRITE-ONCE: the value the \
         dispatch carried is the value the worker sealed the audit chain under"
    );

    // The sweep reads that NULL as the standalone contract and verifies the
    // row under (job_id, job_id) — it is not dropped as "unbound".
    let (targets, standalone) = partition_sweep_rows(&[(trigger, still_null)]);
    assert_eq!((targets.len(), standalone), (1, 1));
    assert_eq!(targets[0].genesis_workflow_id(), trigger.to_string());
    assert!(targets[0].is_standalone());

    // Idempotent against the error-path upserts: a second insert of the same
    // run id is a no-op, not a conflict error.
    talos_engine::workflow_chains::insert_chain_execution_row(
        &pool,
        run,
        wf,
        user,
        Some(actor),
        trigger,
    )
    .await
    .expect("second insert is ON CONFLICT DO NOTHING");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM workflow_executions WHERE id = $1")
        .bind(run)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 1);

    // The archive carries the link too (#749: lineage survives archival), and
    // the archive move's column list names it, or the move would silently drop
    // it on every sweep.
    let archive_has_it: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = \
         'workflow_executions_archive' AND column_name = 'triggered_by_module_execution_id')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(archive_has_it);
    assert!(talos_advanced_repository::archived_execution_column_sql()
        .contains("triggered_by_module_execution_id"));
}
