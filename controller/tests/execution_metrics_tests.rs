//! The last three names in check 58's dead-metric baseline, driven through
//! every PRODUCTION finalizer: `talos_workflow_execution_duration_seconds`,
//! `talos_module_executions_total` and `talos_module_execution_duration_seconds`.
//!
//! Each finalizer now RETURNS `EXTRACT(EPOCH FROM (completed_at -
//! started_at))` from the UPDATE that moved the status, so the histogram
//! describes the same row and the same database clock as the count. These
//! tests back-date `started_at` by a known amount and assert the observed
//! duration is at least that — a finalizer that observed `0.0` for a row
//! that ran five seconds, or observed anything for a row whose
//! `completed_at` was never stamped, fails here.
//!
//! One test, sequential, because the registry is process-global. `common`
//! harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use common::{create_test_user, create_test_workflow, setup_test_context};
use serde_json::json;
use sqlx::{Pool, Postgres};
use talos_execution_repository::ExecutionRepository;
use talos_metrics::ModuleExecutionOutcome;
use talos_module_executions::TriggerType;
use talos_workflow_repository::{ExecutionPriority, WorkflowRepository};
use uuid::Uuid;

async fn backdate_workflow_execution(pool: &Pool<Postgres>, id: Uuid, secs: i64) {
    sqlx::query("UPDATE workflow_executions SET started_at = NOW() - ($2::int * INTERVAL '1 second') WHERE id = $1")
        .bind(id)
        .bind(secs as i32)
        .execute(pool)
        .await
        .expect("backdate workflow execution");
}

async fn backdate_module_execution(pool: &Pool<Postgres>, id: Uuid, secs: i64) {
    sqlx::query("UPDATE module_executions SET started_at = NOW() - ($2::int * INTERVAL '1 second'), status = 'running' WHERE id = $1")
        .bind(id)
        .bind(secs as i32)
        .execute(pool)
        .await
        .expect("backdate module execution");
}

#[tokio::test]
async fn every_finalizer_counts_and_measures_the_row_it_finalized() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "exec_metrics@example.com").await;
    let wf = create_test_workflow(&pool, user, "exec-metrics-wf").await;
    // `workflow_executions.actor_id` / `module_executions.actor_id` are NOT
    // NULL; the harness user has no Default actor, so seed one and bind it.
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, 'exec-metrics-actor')")
        .bind(actor)
        .bind(user)
        .execute(&pool)
        .await
        .expect("seed actor");
    talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
    let m = talos_metrics::global().expect("global metrics installed");

    let wf_count = |status: &str| {
        m.workflow_executions_total
            .with_label_values(&[status])
            .get()
    };
    let wf_hist = |status: &str| {
        m.workflow_execution_duration_seconds
            .with_label_values(&[status])
            .get_sample_count()
    };
    let wf_hist_sum = |status: &str| {
        m.workflow_execution_duration_seconds
            .with_label_values(&[status])
            .get_sample_sum()
    };
    let mod_count = |o: ModuleExecutionOutcome| {
        m.module_executions_total
            .with_label_values(&[o.as_str()])
            .get()
    };
    let mod_hist = |o: ModuleExecutionOutcome| {
        m.module_execution_duration_seconds
            .with_label_values(&[o.as_str()])
            .get_sample_count()
    };

    // ── workflow finalizers ──────────────────────────────────────────────
    let exec_repo = ExecutionRepository::new(pool.clone());
    let wf_repo = WorkflowRepository::new(pool.clone());
    let new_running = |pool: Pool<Postgres>| async move {
        let id = Uuid::new_v4();
        ExecutionRepository::new(pool.clone())
            .insert_test_execution_row(id, wf, user, Some(actor), ExecutionPriority::Normal)
            .await
            .expect("insert running execution");
        backdate_workflow_execution(&pool, id, 5).await;
        id
    };

    // execution-repository success: count +1, one observation of >= 5 s.
    let (c0, h0, s0) = (
        wf_count("success"),
        wf_hist("success"),
        wf_hist_sum("success"),
    );
    let e = new_running(pool.clone()).await;
    exec_repo
        .mark_execution_completed(e, &json!({"ok": true}))
        .await
        .expect("complete");
    assert_eq!(wf_count("success"), c0 + 1.0, "success counted once");
    assert_eq!(wf_hist("success"), h0 + 1, "one duration observed");
    assert!(
        wf_hist_sum("success") - s0 >= 4.9,
        "the observed duration is the row's own age (>= 5 s), got {}",
        wf_hist_sum("success") - s0
    );

    // execution-repository failure.
    let (c0, h0) = (wf_count("failure"), wf_hist("failure"));
    let e = new_running(pool.clone()).await;
    exec_repo
        .mark_execution_failed(e, "boom", None)
        .await
        .expect("fail");
    assert_eq!(wf_count("failure"), c0 + 1.0);
    assert_eq!(wf_hist("failure"), h0 + 1);

    // The THIRD finalizer, which had never counted at all. With completed_at
    // stamped it observes a duration; without, it counts and observes NOTHING
    // — an unknown duration is not zero seconds.
    let (c0, h0) = (wf_count("failure"), wf_hist("failure"));
    let e = new_running(pool.clone()).await;
    let n = exec_repo
        .fail_execution_unless_terminal(e, "late", true)
        .await
        .expect("fail unless terminal (stamped)");
    assert_eq!(n, 1);
    assert_eq!(
        wf_count("failure"),
        c0 + 1.0,
        "fail_execution_unless_terminal now counts"
    );
    assert_eq!(
        wf_hist("failure"),
        h0 + 1,
        "stamped completed_at → a duration"
    );
    let (c0, h0) = (wf_count("failure"), wf_hist("failure"));
    let e = new_running(pool.clone()).await;
    let n = exec_repo
        .fail_execution_unless_terminal(e, "late", false)
        .await
        .expect("fail unless terminal (unstamped)");
    assert_eq!(n, 1);
    assert_eq!(wf_count("failure"), c0 + 1.0);
    assert_eq!(
        wf_hist("failure"),
        h0,
        "no completed_at → no duration observed"
    );
    // A no-op (already terminal) counts nothing.
    let (c0, h0) = (wf_count("failure"), wf_hist("failure"));
    let n = exec_repo
        .fail_execution_unless_terminal(e, "again", true)
        .await
        .expect("no-op");
    assert_eq!(n, 0);
    assert_eq!((wf_count("failure"), wf_hist("failure")), (c0, h0));

    // workflow-repository twins.
    let (c0, h0) = (wf_count("success"), wf_hist("success"));
    let e = new_running(pool.clone()).await;
    wf_repo
        .mark_execution_completed(e, &json!({"ok": true}))
        .await
        .expect("wf-repo complete");
    assert_eq!(
        (wf_count("success"), wf_hist("success")),
        (c0 + 1.0, h0 + 1)
    );
    let (c0, h0) = (wf_count("failure"), wf_hist("failure"));
    let e = new_running(pool.clone()).await;
    wf_repo
        .mark_execution_failed(e, "boom", None)
        .await
        .expect("wf-repo fail");
    assert_eq!(
        (wf_count("failure"), wf_hist("failure")),
        (c0 + 1.0, h0 + 1)
    );

    // ── module finalizers ────────────────────────────────────────────────
    let module_id = Uuid::new_v4();
    sqlx::query("INSERT INTO modules (id, user_id, name, kind) VALUES ($1, $2, 'exec-metrics-module', 'sandbox')")
        .bind(module_id)
        .bind(user)
        .execute(&pool)
        .await
        .expect("insert module");
    let new_module_exec = |pool: Pool<Postgres>,
                           svc: std::sync::Arc<talos_module_executions::ModuleExecutionService>,
                           secs: i64| async move {
        let id = svc
            .create_execution(
                module_id,
                user,
                Uuid::new_v4(),
                TriggerType::Manual,
                None,
                None,
                None,
                Some(actor),
            )
            .await
            .expect("create module execution");
        backdate_module_execution(&pool, id, secs).await;
        id
    };
    use ModuleExecutionOutcome as O;
    // Seeded: every outcome exists at 0 before the first finalizer.
    let rendered = m.render_prometheus().expect("render");
    for o in O::ALL {
        assert!(rendered.contains(&format!(
            "talos_module_executions_total{{status=\"{}\"}}",
            o.as_str()
        )));
    }

    let (c0, h0) = (mod_count(O::Completed), mod_hist(O::Completed));
    let x = new_module_exec(pool.clone(), ctx.execution_service.clone(), 5).await;
    ctx.execution_service
        .complete_execution(x, user, Some(json!({"done": true})), None, None)
        .await
        .expect("complete module execution");
    assert_eq!(
        (mod_count(O::Completed), mod_hist(O::Completed)),
        (c0 + 1.0, h0 + 1)
    );
    let sum = m
        .module_execution_duration_seconds
        .with_label_values(&[O::Completed.as_str()])
        .get_sample_sum();
    assert!(
        sum >= 4.9,
        "duration is the row's own age (>= 5 s), got {sum}"
    );

    let (c0, h0) = (mod_count(O::Failed), mod_hist(O::Failed));
    let x = new_module_exec(pool.clone(), ctx.execution_service.clone(), 5).await;
    ctx.execution_service
        .fail_execution(x, user, "module blew up".to_string(), None)
        .await
        .expect("fail module execution");
    assert_eq!(
        (mod_count(O::Failed), mod_hist(O::Failed)),
        (c0 + 1.0, h0 + 1)
    );

    let (c0, h0) = (mod_count(O::Timeout), mod_hist(O::Timeout));
    let x = new_module_exec(pool.clone(), ctx.execution_service.clone(), 5).await;
    ctx.execution_service
        .timeout_execution(x, user)
        .await
        .expect("timeout module execution");
    assert_eq!(
        (mod_count(O::Timeout), mod_hist(O::Timeout)),
        (c0 + 1.0, h0 + 1)
    );

    // The stuck sweep: a row 61 minutes old, swept at a 30-minute threshold,
    // is one more timeout with the age it had reached.
    let (c0, h0) = (mod_count(O::Timeout), mod_hist(O::Timeout));
    let _stuck = new_module_exec(pool.clone(), ctx.execution_service.clone(), 61 * 60).await;
    let swept = ctx
        .execution_service
        .cleanup_stuck_executions(30)
        .await
        .expect("sweep");
    assert_eq!(swept, 1, "exactly the back-dated row is swept");
    assert_eq!(
        (mod_count(O::Timeout), mod_hist(O::Timeout)),
        (c0 + 1.0, h0 + 1)
    );
    let sum = m
        .module_execution_duration_seconds
        .with_label_values(&[O::Timeout.as_str()])
        .get_sample_sum();
    assert!(
        sum >= 61.0 * 60.0,
        "the swept row's age is what was observed, got {sum}"
    );

    // A finalizer that matches no row counts nothing.
    let (c0, h0) = (mod_count(O::Failed), mod_hist(O::Failed));
    assert!(ctx
        .execution_service
        .fail_execution(Uuid::new_v4(), user, "ghost".to_string(), None)
        .await
        .is_err());
    assert_eq!((mod_count(O::Failed), mod_hist(O::Failed)), (c0, h0));

    // ── the ENGINE's finalizer ───────────────────────────────────────────
    // `PostgresModuleExecutionStore::record_completed` is what every
    // workflow-dispatched module row is finalized through (sole caller:
    // `finalize_module_execution_row`), and #814 wired every finalizer but
    // this one — the post-deploy reconciliation read 14 completed rows
    // against a counter at 0. Drive it with the three status strings the
    // engine passes (`classify` in `engine_dispatch_single`).
    use talos_workflow_engine_core::ModuleExecutionStore as _;
    let store =
        talos_engine::module_execution_store::PostgresModuleExecutionStore::new(pool.clone());
    for (status, outcome) in [
        ("completed", O::Completed),
        ("failed", O::Failed),
        ("timeout", O::Timeout),
    ] {
        let (c0, h0) = (mod_count(outcome), mod_hist(outcome));
        let s0 = m
            .module_execution_duration_seconds
            .with_label_values(&[outcome.as_str()])
            .get_sample_sum();
        let x = new_module_exec(pool.clone(), ctx.execution_service.clone(), 7).await;
        store
            .record_completed(x, status, &json!({"via": "engine"}), Some(7000), None)
            .await
            .expect("engine store finalizes the running row");
        assert_eq!(
            (mod_count(outcome), mod_hist(outcome)),
            (c0 + 1.0, h0 + 1),
            "engine store `{status}` counts and measures exactly once"
        );
        let s1 = m
            .module_execution_duration_seconds
            .with_label_values(&[outcome.as_str()])
            .get_sample_sum();
        assert!(
            s1 - s0 >= 6.9,
            "engine store `{status}` observed the row's own age (>= 7 s), got {}",
            s1 - s0
        );
    }
    // The engine store refuses a row that is not pending/running and counts
    // nothing for it — a second finalize of the row above is such a refusal.
    let (c0, h0) = (mod_count(O::Completed), mod_hist(O::Completed));
    let x = new_module_exec(pool.clone(), ctx.execution_service.clone(), 1).await;
    store
        .record_completed(x, "completed", &json!({}), None, None)
        .await
        .expect("first finalize");
    // The store answers `Ok(())` for a refused re-finalize by design (it
    // logs at debug and lets the engine carry on); what must hold is that
    // the refusal COUNTED NOTHING.
    store
        .record_completed(x, "completed", &json!({}), None, None)
        .await
        .expect("a refused re-finalize is Ok(()), not an error");
    assert_eq!(
        (mod_count(O::Completed), mod_hist(O::Completed)),
        (c0 + 1.0, h0 + 1),
        "the refused re-finalize counted nothing"
    );

    // ── sibling cancellation: the ONE home for six former copies ─────────
    // Two running module rows under one workflow execution, back-dated 5 s,
    // plus a THIRD under a different workflow execution that must be left
    // alone. Both cancelled rows are counted with their age; the control
    // row is neither cancelled nor counted.
    let wf_exec = new_running(pool.clone()).await;
    let other_exec = new_running(pool.clone()).await;
    let bound_module_exec =
        |pool: Pool<Postgres>,
         svc: std::sync::Arc<talos_module_executions::ModuleExecutionService>,
         wf_exec: Uuid| async move {
            let id = svc
                .create_execution(
                    module_id,
                    user,
                    Uuid::new_v4(),
                    TriggerType::Manual,
                    None,
                    None,
                    Some(wf_exec),
                    Some(actor),
                )
                .await
                .expect("create bound module execution");
            backdate_module_execution(&pool, id, 5).await;
            id
        };
    let a = bound_module_exec(pool.clone(), ctx.execution_service.clone(), wf_exec).await;
    let b = bound_module_exec(pool.clone(), ctx.execution_service.clone(), wf_exec).await;
    let control = bound_module_exec(pool.clone(), ctx.execution_service.clone(), other_exec).await;
    let (c0, h0) = (mod_count(O::Cancelled), mod_hist(O::Cancelled));
    let s0 = m
        .module_execution_duration_seconds
        .with_label_values(&[O::Cancelled.as_str()])
        .get_sample_sum();
    let cancelled = talos_workflow_repository::cancel_running_module_executions(
        &pool,
        wf_exec,
        talos_workflow_repository::SiblingCancelReason::WorkflowTimedOut,
    )
    .await
    .expect("cancel siblings");
    assert_eq!(cancelled, 2, "exactly the two siblings of wf_exec");
    assert_eq!(
        (mod_count(O::Cancelled), mod_hist(O::Cancelled)),
        (c0 + 2.0, h0 + 2),
        "one count and one observation PER cancelled row"
    );
    let s1 = m
        .module_execution_duration_seconds
        .with_label_values(&[O::Cancelled.as_str()])
        .get_sample_sum();
    assert!(
        s1 - s0 >= 9.8,
        "two rows of >= 5 s each were observed, got {}",
        s1 - s0
    );
    let rows: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT id, status, error_message FROM module_executions WHERE id = ANY($1) ORDER BY id",
    )
    .bind(vec![a, b, control])
    .fetch_all(&pool)
    .await
    .expect("read rows back");
    for (id, status, err) in &rows {
        if *id == control {
            assert_eq!(status, "running", "the other workflow's row is untouched");
            assert_eq!(err.as_deref(), None);
        } else {
            assert_eq!(status, "cancelled");
            assert_eq!(
                err.as_deref(),
                Some(talos_workflow_repository::SiblingCancelReason::WorkflowTimedOut.message()),
                "the row says WHY it was cancelled"
            );
        }
    }
    // Idempotent: a second sweep finds no running sibling and counts nothing.
    let (c0, h0) = (mod_count(O::Cancelled), mod_hist(O::Cancelled));
    let again = talos_workflow_repository::cancel_running_module_executions(
        &pool,
        wf_exec,
        talos_workflow_repository::SiblingCancelReason::WorkflowFailed,
    )
    .await
    .expect("second sweep");
    assert_eq!(again, 0);
    assert_eq!((mod_count(O::Cancelled), mod_hist(O::Cancelled)), (c0, h0));
}
