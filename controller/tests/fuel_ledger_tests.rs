//! The fuel ledger records EVERY verified dispatch attempt, and the actor's
//! hourly fuel budget counts it (2026-09-29).
//!
//! Until this package the rollup was written only for a node that COMPLETED
//! with a JSON-object output carrying `__fuel_consumed__`, so a failed or
//! fuel-exhausted attempt, a retried attempt, a loop body, a module-bound
//! dispatch and any non-object output spent fuel the budget never saw.
//! `talos_cost_attribution` is now the one writer of both fuel ledgers.
//!
//! Each test drives the PRODUCTION recorder, admission and learner read
//! against a real clone. `common` harness (a template clone per test), so
//! CTRL_TESTS (64b).

mod common;

use sqlx::{Pool, Postgres};
use talos_cost_attribution::{AttemptOutcome, DispatchFuel, ModuleBoundFuelRecord};
use uuid::Uuid;

struct Fixture {
    user: Uuid,
    actor: Uuid,
    module: Uuid,
    wf: Uuid,
}

async fn fixture(pool: &Pool<Postgres>) -> Fixture {
    let user = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'fuel')")
        .bind(user)
        .bind(format!("fuel-ledger-{user}@example.com"))
        .execute(pool)
        .await
        .expect("seed user");
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(actor)
        .bind(user)
        .bind(format!("fuel-actor-{actor}"))
        .execute(pool)
        .await
        .expect("seed actor");
    let module = Uuid::new_v4();
    sqlx::query("INSERT INTO modules (id, name, kind) VALUES ($1, $2, 'sandbox')")
        .bind(module)
        .bind(format!("fuel-module-{module}"))
        .execute(pool)
        .await
        .expect("seed module");
    let wf = common::create_test_workflow(pool, user, &format!("fuel-wf-{actor}")).await;
    Fixture {
        user,
        actor,
        module,
        wf,
    }
}

async fn seed_module_execution(pool: &Pool<Postgres>, f: &Fixture) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO module_executions (id, module_id, user_id, actor_id, status, trigger_type) \
         VALUES ($1, $2, $3, $4, 'running', 'webhook')",
    )
    .bind(id)
    .bind(f.module)
    .bind(f.user)
    .bind(f.actor)
    .execute(pool)
    .await
    .expect("seed module execution");
    id
}

fn attempt(f: &Fixture, row: Uuid, consumed: u64, outcome: AttemptOutcome) -> DispatchFuel {
    DispatchFuel {
        module_execution_id: row,
        execution_id: Uuid::new_v4(),
        workflow_id: Some(f.wf),
        node_label: Some("summarise".into()),
        module_id: Some(f.module),
        actor_id: Some(f.actor),
        root_actor_id: None,
        consumed,
        limit: Some(5_000),
        wall_time_ms: 12,
        outcome,
    }
}

async fn admit(pool: &Pool<Postgres>, actor: Uuid) -> talos_actor_budget_refusal::BudgetAdmission {
    let mut tx = pool.begin().await.expect("begin");
    let got = talos_actor_budget_refusal::admit_actor_budget(&mut tx, actor)
        .await
        .expect("admission");
    tx.rollback().await.expect("rollback");
    got
}

/// THE budget property. A FAILED attempt's fuel is charged to the actor: an
/// actor at its hourly fuel cap only through failed attempts is refused.
/// The control is the same actor before the attempt, which is admitted.
#[tokio::test]
async fn a_failed_attempt_counts_toward_the_hourly_fuel_budget() {
    let (pool, _db) = common::isolated_db_pool().await;
    let f = fixture(&pool).await;
    sqlx::query(
        "INSERT INTO actor_budget_policies (actor_id, max_fuel_per_hour, on_budget_exceeded) \
         VALUES ($1, 1000, 'block')",
    )
    .bind(f.actor)
    .execute(&pool)
    .await
    .expect("seed policy");
    let row = seed_module_execution(&pool, &f).await;

    assert_eq!(
        admit(&pool, f.actor).await,
        talos_actor_budget_refusal::BudgetAdmission::Admitted,
        "control: nothing spent yet"
    );

    talos_cost_attribution::record_dispatch_fuel(
        &pool,
        &attempt(&f, row, 1_000, AttemptOutcome::Failed),
    )
    .await
    .expect("record");

    match admit(&pool, f.actor).await {
        talos_actor_budget_refusal::BudgetAdmission::Refused(r) => {
            assert_eq!(r.cap, talos_actor_budget_refusal::BudgetCap::FuelPerHour);
            assert_eq!(r.used, 1_000);
        }
        other => panic!("a failed attempt's fuel must count: {other:?}"),
    }
}

/// Both ledgers are written, with the controller's identity; a retried
/// attempt of the same row ADDS to its `fuel_consumed`, and each attempt is
/// its own rollup row carrying its outcome.
#[tokio::test]
async fn both_ledgers_record_each_attempt_and_the_row_sums_retries() {
    let (pool, _db) = common::isolated_db_pool().await;
    let f = fixture(&pool).await;
    let row = seed_module_execution(&pool, &f).await;

    for (consumed, outcome) in [
        (400, AttemptOutcome::Failed),
        (600, AttemptOutcome::Completed),
    ] {
        talos_cost_attribution::record_dispatch_fuel(&pool, &attempt(&f, row, consumed, outcome))
            .await
            .expect("record");
    }

    let total: Option<i64> =
        sqlx::query_scalar("SELECT fuel_consumed FROM module_executions WHERE id = $1")
            .bind(row)
            .fetch_one(&pool)
            .await
            .expect("read row");
    assert_eq!(total, Some(1_000), "the row is the sum of its attempts");

    let rows: Vec<(
        Option<Uuid>,
        Option<Uuid>,
        Option<String>,
        Option<Uuid>,
        i64,
        Option<i64>,
        String,
    )> = sqlx::query_as(
        "SELECT actor_id, workflow_id, node_id, module_id, fuel_consumed, max_fuel, outcome \
             FROM execution_cost_rollup WHERE actor_id = $1 ORDER BY fuel_consumed",
    )
    .bind(f.actor)
    .fetch_all(&pool)
    .await
    .expect("read rollup");
    let want = |fuel: i64, outcome: &str| {
        (
            Some(f.actor),
            Some(f.wf),
            Some("summarise".to_string()),
            Some(f.module),
            fuel,
            Some(5_000),
            outcome.to_string(),
        )
    };
    assert_eq!(rows, vec![want(400, "failed"), want(600, "completed")]);
}

/// A module-bound attempt (webhook, push, DLQ replay) takes its identity from
/// its own `module_executions` row, never from the caller: actor and module
/// come from the row, and there is no workflow or node. An unknown row writes
/// nothing.
#[tokio::test]
async fn module_bound_fuel_takes_its_identity_from_the_row() {
    let (pool, _db) = common::isolated_db_pool().await;
    let f = fixture(&pool).await;
    let row = seed_module_execution(&pool, &f).await;

    let found = talos_cost_attribution::record_module_bound_fuel(
        &pool,
        row,
        "1760000000:nonce-a",
        250,
        Some(1_000),
        9,
        AttemptOutcome::Completed,
    )
    .await
    .expect("record");
    assert_eq!(found, ModuleBoundFuelRecord::Recorded);

    let got: (
        Option<Uuid>,
        Option<Uuid>,
        Uuid,
        Option<String>,
        Option<Uuid>,
        i64,
        String,
    ) = sqlx::query_as(
        "SELECT actor_id, workflow_id, execution_id, node_id, module_id, fuel_consumed, outcome \
             FROM execution_cost_rollup WHERE module_id = $1",
    )
    .bind(f.module)
    .fetch_one(&pool)
    .await
    .expect("read rollup");
    assert_eq!(
        got,
        (
            Some(f.actor),
            None,
            row,
            None,
            Some(f.module),
            250,
            "completed".to_string()
        )
    );
    let total: Option<i64> =
        sqlx::query_scalar("SELECT fuel_consumed FROM module_executions WHERE id = $1")
            .bind(row)
            .fetch_one(&pool)
            .await
            .expect("read row");
    assert_eq!(total, Some(250));

    let unknown = talos_cost_attribution::record_module_bound_fuel(
        &pool,
        Uuid::new_v4(),
        "1760000000:nonce-b",
        250,
        None,
        9,
        AttemptOutcome::Failed,
    )
    .await
    .expect("record");
    assert_eq!(
        unknown,
        ModuleBoundFuelRecord::NoRow,
        "no row, nothing written"
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM execution_cost_rollup")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(count, 1);
}

/// Security review 2026-10-14, B-1: one signed result's fuel is recorded
/// ONCE, however many times it is delivered. The observer's replay cache is
/// per replica, so a copy of a result delivered to another replica of the
/// queue group passes its verify; the ledger is where it must stop. A second
/// result (a different nonce) for the same attempt row is a different
/// delivery and is counted.
#[tokio::test]
async fn a_module_bound_results_fuel_is_recorded_once_per_signed_result() {
    let (pool, _db) = common::isolated_db_pool().await;
    let f = fixture(&pool).await;
    let row = seed_module_execution(&pool, &f).await;

    let record = |nonce: &'static str| {
        let pool = pool.clone();
        async move {
            talos_cost_attribution::record_module_bound_fuel(
                &pool,
                row,
                nonce,
                250,
                Some(1_000),
                9,
                AttemptOutcome::Completed,
            )
            .await
            .expect("record")
        }
    };
    assert_eq!(
        record("1760000000:once").await,
        ModuleBoundFuelRecord::Recorded
    );
    for _ in 0..3 {
        assert_eq!(
            record("1760000000:once").await,
            ModuleBoundFuelRecord::AlreadyRecorded
        );
    }
    let fuel_and_rows = || async {
        let total: Option<i64> =
            sqlx::query_scalar("SELECT fuel_consumed FROM module_executions WHERE id = $1")
                .bind(row)
                .fetch_one(&pool)
                .await
                .expect("read row");
        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM execution_cost_rollup WHERE execution_id = $1",
        )
        .bind(row)
        .fetch_one(&pool)
        .await
        .expect("count");
        (total, rows)
    };
    assert_eq!(
        fuel_and_rows().await,
        (Some(250), 1),
        "a repeat changes nothing"
    );

    assert_eq!(
        record("1760000000:other").await,
        ModuleBoundFuelRecord::Recorded
    );
    assert_eq!(fuel_and_rows().await, (Some(500), 2));
}

/// The learner must not be fed its own exhaustions: adaptive fuel ceilings
/// read completed attempts only. Five fuel-exhausted attempts at 5 000 beside
/// five completed ones at 100 must learn from the 100s.
#[tokio::test]
async fn learned_fuel_stats_ignore_failed_attempts() {
    let (pool, _db) = common::isolated_db_pool().await;
    let f = fixture(&pool).await;
    let row = seed_module_execution(&pool, &f).await;
    for _ in 0..5 {
        for (consumed, outcome) in [
            (100, AttemptOutcome::Completed),
            (5_000, AttemptOutcome::Failed),
        ] {
            talos_cost_attribution::record_dispatch_fuel(
                &pool,
                &attempt(&f, row, consumed, outcome),
            )
            .await
            .expect("record");
        }
    }
    let stats = talos_analytics_repository::AnalyticsRepository::new(pool.clone())
        .get_workflow_node_fuel_stats(f.wf, 30, 5)
        .await
        .expect("stats");
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].executions, 5, "completed attempts only");
    assert_eq!(stats[0].fuel_max, 100);
}

/// The module-bound path, driven through the PRODUCTION result observer (the
/// finalizer for Gmail/Calendar/GCP push and DLQ-replay results): a FAILED
/// verified result's out-of-band fuel reaches both ledgers under the row's
/// own actor, and counts toward the budget. Before this package the observer
/// recorded no fuel at all, success or failure.
#[tokio::test]
async fn the_result_observer_records_a_failed_attempts_fuel() {
    use talos_workflow_job_protocol::{FuelMeasure, JobResult, JobStatus};
    let (pool, _db) = common::isolated_db_pool().await;
    let f = fixture(&pool).await;
    let row = seed_module_execution(&pool, &f).await;

    let key = b"fuel-ledger-observer-key-0123456789abcdef".to_vec();
    let mut result = JobResult {
        dispatch_attempt: 0,
        workflow_execution_id: None,
        job_id: row,
        status: JobStatus::Failed,
        // A failed attempt has no in-band figure; only the signed field
        // carries its spend.
        output_payload: serde_json::json!({"error": "fuel exhausted"}).into(),
        logs: vec![],
        execution_time_ms: 7,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
        crypto_scheme: 0,
        llm_usage: vec![],
        fuel: Some(FuelMeasure {
            consumed: 800,
            limit: 800,
        }),
    };
    result
        .sign_with_worker_id(&key, "worker-test")
        .expect("sign");
    let ring = talos_workflow_engine_core::WorkerKeyRing::new(
        talos_workflow_engine_core::WorkerSharedKey::new(key),
        [],
    );
    let svc = talos_module_executions::ModuleExecutionService::new(
        pool.clone(),
        std::sync::Arc::new(talos_dlp_provider::DlpService::from_env()),
    );
    talos_job_result_observer::handle_result_message(
        &serde_json::to_vec(&result).expect("serialize"),
        &svc,
        Some(&ring),
    )
    .await;

    common::eventually_default("the observer's fuel record lands", || {
        let pool = pool.clone();
        async move {
            let n: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM execution_cost_rollup WHERE execution_id = $1",
            )
            .bind(row)
            .fetch_one(&pool)
            .await
            .expect("count");
            n == 1
        }
    })
    .await;
    let got: (Option<Uuid>, i64, String) = sqlx::query_as(
        "SELECT actor_id, fuel_consumed, outcome FROM execution_cost_rollup WHERE execution_id = $1",
    )
    .bind(row)
    .fetch_one(&pool)
    .await
    .expect("read rollup");
    assert_eq!(got, (Some(f.actor), 800, "failed".to_string()));
    let total: Option<i64> =
        sqlx::query_scalar("SELECT fuel_consumed FROM module_executions WHERE id = $1")
            .bind(row)
            .fetch_one(&pool)
            .await
            .expect("read row");
    assert_eq!(total, Some(800));
}

/// A second actor of the fixture's user, for a child bound to its own actor.
async fn second_actor(pool: &Pool<Postgres>, f: &Fixture) -> Uuid {
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(actor)
        .bind(f.user)
        .bind(format!("fuel-child-actor-{actor}"))
        .execute(pool)
        .await
        .expect("seed second actor");
    actor
}

/// A child run's fuel is charged to the ROOT run's actor too (security
/// review 2026-10-14, G-8): a root actor at its fuel cap only through a child
/// bound to another actor is refused; a child that inherited the root's actor
/// is counted once, not twice.
#[tokio::test]
async fn a_childs_fuel_is_charged_to_the_root_runs_actor_once() {
    let (pool, _db) = common::isolated_db_pool().await;
    let f = fixture(&pool).await;
    let child_actor = second_actor(&pool, &f).await;
    sqlx::query(
        "INSERT INTO actor_budget_policies (actor_id, max_fuel_per_hour, on_budget_exceeded) \
         VALUES ($1, 1000, 'block')",
    )
    .bind(f.actor)
    .execute(&pool)
    .await
    .expect("seed policy");
    let row = seed_module_execution(&pool, &f).await;

    // A child bound to its own actor spent 600; another, inheriting the
    // root's actor, spent 400.
    let mut bound = attempt(&f, row, 600, AttemptOutcome::Completed);
    bound.actor_id = Some(child_actor);
    bound.root_actor_id = Some(f.actor);
    talos_cost_attribution::record_dispatch_fuel(&pool, &bound)
        .await
        .expect("record");
    let mut inherited = attempt(&f, row, 400, AttemptOutcome::Completed);
    inherited.root_actor_id = Some(f.actor);
    talos_cost_attribution::record_dispatch_fuel(&pool, &inherited)
        .await
        .expect("record");

    assert_eq!(
        talos_actor_budget_refusal::fuel_last_hour(&pool, f.actor)
            .await
            .unwrap(),
        1_000,
        "the root is charged both children, each once"
    );
    assert_eq!(
        talos_actor_budget_refusal::fuel_last_hour(&pool, child_actor)
            .await
            .unwrap(),
        600,
        "the child's own actor is charged what it ran"
    );
    match admit(&pool, f.actor).await {
        talos_actor_budget_refusal::BudgetAdmission::Refused(r) => {
            assert_eq!(r.cap, talos_actor_budget_refusal::BudgetCap::FuelPerHour);
        }
        other => panic!("the root's next run must be refused: {other:?}"),
    }
}

/// A child run is asked about its actor's hourly fuel cap before it starts
/// (G-8): under the cap it starts, at the cap it is refused and the refusal
/// is recorded; an actor with no policy is not limited.
#[tokio::test]
async fn a_child_run_is_refused_when_its_actor_has_spent_its_fuel() {
    use talos_workflow_engine_core::ChildRunAdmission;
    let (pool, _db) = common::isolated_db_pool().await;
    let f = fixture(&pool).await;
    let unlimited = second_actor(&pool, &f).await;
    sqlx::query(
        "INSERT INTO actor_budget_policies (actor_id, max_fuel_per_hour, on_budget_exceeded) \
         VALUES ($1, 1000, 'block')",
    )
    .bind(f.actor)
    .execute(&pool)
    .await
    .expect("seed policy");
    let admission = talos_engine::child_run_admission::PostgresChildRunAdmission::new(pool.clone());

    assert_eq!(
        admission.admit_child_run(f.actor).await,
        Ok(()),
        "nothing spent"
    );
    let row = seed_module_execution(&pool, &f).await;
    talos_cost_attribution::record_dispatch_fuel(
        &pool,
        &attempt(&f, row, 1_000, AttemptOutcome::Completed),
    )
    .await
    .expect("record");
    let refused = admission
        .admit_child_run(f.actor)
        .await
        .expect_err("the cap is spent");
    assert!(refused.contains("fuel"), "{refused}");
    assert_eq!(admission.admit_child_run(unlimited).await, Ok(()));
}
