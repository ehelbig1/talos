//! What a controller does with the runs it is driving when it shuts down:
//! `talos_execution_orchestration::shutdown_drain::drain_in_flight_runs`,
//! driven against real rows. ONE counter-reading test function, because the
//! metrics registry is a process global.
mod common;

use sqlx::{Pool, Postgres};
use std::time::Duration;
use talos_execution_orchestration::shutdown_drain::{
    drain_in_flight_runs, INTERRUPTED_BY_SHUTDOWN,
};
use talos_shutdown::inflight::InFlightRuns;
use uuid::Uuid;

struct Seeded {
    user: Uuid,
    workflow: Uuid,
    actor: Uuid,
}

async fn seed_tenant(pool: &Pool<Postgres>) -> Seeded {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@wf-fail.test"))
    .execute(pool)
    .await
    .unwrap();
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("wforg-{tag}"))
    .bind(format!("wforg-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .unwrap();
    let workflow = Uuid::new_v4();
    sqlx::query("INSERT INTO workflows (id, user_id, org_id, name, module_uri, graph_json) VALUES ($1, $2, $3, $4, 'test://none', '{}'::jsonb)")
        .bind(workflow)
        .bind(user)
        .bind(org)
        .bind(format!("wf-{tag}"))
        .execute(pool)
        .await
        .unwrap();
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, $3, $4)")
        .bind(actor)
        .bind(user)
        .bind(format!("wfactor-{tag}"))
        .bind(org)
        .execute(pool)
        .await
        .unwrap();
    Seeded {
        user,
        workflow,
        actor,
    }
}

async fn new_execution(pool: &Pool<Postgres>, t: &Seeded, status: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status, started_at) VALUES ($1, $2, $3, $4, $5, NOW() - interval '3 seconds')",
    )
    .bind(id)
    .bind(t.workflow)
    .bind(t.user)
    .bind(t.actor)
    .bind(status)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn status_of(pool: &Pool<Postgres>, id: Uuid) -> (String, Option<String>) {
    sqlx::query_as("SELECT status, error_message FROM workflow_executions WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn new_module_row(pool: &Pool<Postgres>, t: &Seeded, wf_exec: Uuid) -> Uuid {
    let module = Uuid::new_v4();
    sqlx::query("INSERT INTO modules (id, name, kind) VALUES ($1, $2, 'sandbox')")
        .bind(module)
        .bind(format!("m-{module}"))
        .execute(pool)
        .await
        .unwrap();
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO module_executions (id, module_id, user_id, actor_id, workflow_execution_id, status, trigger_type) \
         VALUES ($1, $2, $3, $4, $5, 'running', 'webhook')",
    )
    .bind(id)
    .bind(module)
    .bind(t.user)
    .bind(t.actor)
    .bind(wf_exec)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn module_status(pool: &Pool<Postgres>, id: Uuid) -> (String,) {
    sqlx::query_as("SELECT status FROM module_executions WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn shutdown_waits_for_its_own_runs_and_fails_only_what_outlasts_the_grace() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
    let failures = || {
        talos_metrics::global()
            .expect("metrics")
            .workflow_executions_total
            .with_label_values(&["failure"])
            .get()
    };

    // ── A run that finishes inside the grace: waited for, nothing failed.
    {
        let runs = InFlightRuns::new();
        let quick = new_execution(&pool, &t, "running").await;
        let guard = runs.track(quick);
        let finisher = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            drop(guard);
        });
        let before = failures();
        let report = drain_in_flight_runs(&pool, &runs, Duration::from_secs(20)).await;
        finisher.await.unwrap();
        assert_eq!(
            (
                report.in_flight_at_start,
                report.outlasted_grace,
                report.failed_now
            ),
            (1, 0, Some(0))
        );
        assert!(
            report.waited >= Duration::from_millis(140),
            "{:?}",
            report.waited
        );
        assert_eq!(
            status_of(&pool, quick).await.0,
            "running",
            "the drain writes nothing here"
        );
        assert_eq!(failures(), before);
    }

    // ── Runs that outlast the grace are failed NOW; nothing else is touched.
    let runs = InFlightRuns::new();
    let slow = new_execution(&pool, &t, "running").await;
    let resumed = new_execution(&pool, &t, "resuming").await;
    let finished_itself = new_execution(&pool, &t, "completed").await;
    // A sibling replica's live run: `running`, and NOT in this process's set.
    let siblings = new_execution(&pool, &t, "running").await;
    let slow_module = new_module_row(&pool, &t, slow).await;
    let siblings_module = new_module_row(&pool, &t, siblings).await;
    let _guards = [
        runs.track(slow),
        runs.track(resumed),
        runs.track(finished_itself),
    ];

    let before = failures();
    let report = drain_in_flight_runs(&pool, &runs, Duration::from_millis(120)).await;
    assert_eq!(report.in_flight_at_start, 3);
    assert_eq!(report.outlasted_grace, 3);
    assert_eq!(
        report.failed_now,
        Some(2),
        "the run that reached a real terminal status keeps it"
    );
    assert!(report.waited >= Duration::from_millis(120));

    for id in [slow, resumed] {
        assert_eq!(
            status_of(&pool, id).await,
            (
                "failed".to_string(),
                Some(INTERRUPTED_BY_SHUTDOWN.to_string())
            )
        );
    }
    assert_eq!(status_of(&pool, finished_itself).await.0, "completed");
    assert_eq!(
        status_of(&pool, siblings).await,
        ("running".to_string(), None),
        "a run this process is not driving must never be failed by its shutdown"
    );
    assert_eq!(
        failures() - before,
        2.0,
        "each run failed at shutdown is a counted failure"
    );
    // The `cancel_siblings_on_workflow_fail` trigger closes the failed run's
    // module rows; the sibling replica's are untouched.
    assert_eq!(module_status(&pool, slow_module).await.0, "cancelled");
    assert_eq!(module_status(&pool, siblings_module).await.0, "running");

    // Idempotent: a second pass over the same set fails nothing more.
    let again = drain_in_flight_runs(&pool, &runs, Duration::from_millis(10)).await;
    assert_eq!(again.failed_now, Some(0));
    assert_eq!(failures() - before, 2.0);
}

/// Shutdown must end even when the database is gone: the failure is
/// disclosed (`failed_now: None`), never a panic or a hang.
#[tokio::test]
async fn an_unreachable_database_does_not_stop_the_shutdown() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let stuck = new_execution(&pool, &t, "running").await;
    let runs = InFlightRuns::new();
    let _guard = runs.track(stuck);
    let dead = pool.clone();
    dead.close().await;
    let report = tokio::time::timeout(
        Duration::from_secs(20),
        drain_in_flight_runs(&dead, &runs, Duration::from_millis(50)),
    )
    .await
    .expect("the drain must return");
    assert_eq!((report.outlasted_grace, report.failed_now), (1, None));
}

/// TEXTUAL, stated as such — none of these can be driven without a live
/// controller process, NATS and a signal.
#[test]
fn the_shutdown_sequence_is_wired_in_order() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let read =
        |p: &str| std::fs::read_to_string(root.join(p)).unwrap_or_else(|e| panic!("{p}: {e}"));
    let code = |s: &str| {
        s.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    };

    // Every engine-run chokepoint tracks its run.
    let nats_run = code(&read("talos-engine/src/nats_run.rs"));
    assert_eq!(
        nats_run
            .matches("talos_shutdown::inflight::global().track(execution_id)")
            .count(),
        3,
        "run_with_nats, run_with_seed_via_nats and run_with_trigger_input_via_nats"
    );

    // The scheduler claims nothing once the drain has begun.
    let scheduler = code(&read("talos-scheduler/src/lib.rs"));
    let poll = &scheduler[scheduler
        .find("async fn poll_and_trigger")
        .expect("poll fn")..];
    let drain_check = poll
        .find("inflight::global().is_draining()")
        .expect("drain check");
    let claim = poll.find("select_due_and_advance(").expect("claim");
    assert!(
        drain_check < claim,
        "the drain check must precede the claim"
    );

    // main: begin_drain at the signal; the RPC / background / DLQ stop signals
    // only AFTER the drain, because a draining run still needs them.
    let main = code(&read("controller/src/main.rs"));
    let serve = &main[main.find("async fn serve(").expect("serve fn")..];
    let at = |needle: &str| {
        serve
            .find(needle)
            .unwrap_or_else(|| panic!("`{needle}` missing"))
    };
    let (signal, begin, drain) = (
        at("talos_shutdown::wait_for_shutdown().await"),
        at("inflight::global().begin_drain()"),
        at("shutdown_drain::drain_in_flight_runs("),
    );
    assert!(signal < begin && begin < drain);
    assert!(at("RUN_DRAIN_GRACE") > drain);
    for after in [
        "shutdown_dlq()",
        "rpc_shutdown_tx.send(true)",
        "bg_shutdown_tx.send(true)",
    ] {
        assert!(
            at(after) > at("_report = &mut drain"),
            "`{after}` must come after the drain completes"
        );
    }
}
