//! Postgres-backed integration test for `ActorRepository::check_execution_allowed`'s
//! auto-suspend terminal-state guard (MCP-646).
//!
//! When an actor exceeds its budget with `on_budget_exceeded = 'suspend'`, the
//! enforcement auto-suspends it — but the UPDATE is guarded by
//! `status NOT IN ('archived', 'terminated')` so it can NEVER clobber an
//! ARCHIVED actor's status. Archiving is documented as IRREVERSIBLE; a budget
//! trip must not silently flip `archived` → `suspended`. This exercises the
//! REAL method end-to-end and pins both halves: the guard spares an archived
//! actor, and a normal active actor IS suspended (positive control, so the
//! test can't pass by the guard being over-broad).
//!
//! Skipped (green) unless `TALOS_TEST_DATABASE_URL` is set. Run locally:
//!
//! ```bash
//! docker run -d --rm -e POSTGRES_PASSWORD=test -e POSTGRES_DB=talos \
//!   -p 15434:5432 postgres:16-alpine
//! TALOS_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:15434/talos \
//!   cargo test -p talos-actor-repository --test budget_guard_integration
//! ```

use sqlx::{Executor, PgPool};
use talos_actor_repository::ActorRepository;

macro_rules! pool_or_skip {
    () => {
        match std::env::var("TALOS_TEST_DATABASE_URL") {
            Ok(url) => PgPool::connect(&url).await.expect("connect to test PG"),
            Err(_) => {
                eprintln!("skipping: TALOS_TEST_DATABASE_URL is not set");
                return;
            }
        }
    };
}

/// Minimal schema covering exactly the columns `check_execution_allowed`
/// touches: actors.status, actor_budget_policies.{max_executions_per_hour,
/// max_executions_total, on_budget_exceeded}, and workflow_executions for the
/// count helpers.
async fn setup(pool: &PgPool) {
    pool.execute(
        "DROP TABLE IF EXISTS workflow_executions CASCADE; \
         DROP TABLE IF EXISTS actor_budget_policies CASCADE; \
         DROP TABLE IF EXISTS actors CASCADE; \
         CREATE TABLE actors ( \
            id uuid PRIMARY KEY, status text NOT NULL, \
            updated_at timestamptz NOT NULL DEFAULT now()); \
         CREATE TABLE actor_budget_policies ( \
            actor_id uuid PRIMARY KEY, \
            max_executions_per_hour int, \
            max_executions_total bigint, \
            on_budget_exceeded text NOT NULL); \
         CREATE TABLE workflow_executions ( \
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(), \
            actor_id uuid, \
            started_at timestamptz NOT NULL DEFAULT now());",
    )
    .await
    .unwrap();
}

async fn seed_actor(pool: &PgPool, id: uuid::Uuid, status: &str) {
    sqlx::query("INSERT INTO actors (id, status) VALUES ($1, $2)")
        .bind(id)
        .bind(status)
        .execute(pool)
        .await
        .unwrap();
    // A policy that trips on the FIRST execution (0/hour) and suspends.
    sqlx::query(
        "INSERT INTO actor_budget_policies \
           (actor_id, max_executions_per_hour, max_executions_total, on_budget_exceeded) \
         VALUES ($1, 0, NULL, 'suspend')",
    )
    .bind(id)
    .execute(pool)
    .await
    .unwrap();
}

async fn status_of(pool: &PgPool, id: uuid::Uuid) -> String {
    sqlx::query_scalar::<_, String>("SELECT status FROM actors WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn budget_auto_suspend_spares_archived_but_suspends_active() {
    let pool = pool_or_skip!();
    setup(&pool).await;
    let repo = ActorRepository::new(pool.clone());

    // ── Guard half: an ARCHIVED actor over budget must NOT be clobbered. ──
    let archived = uuid::Uuid::new_v4();
    seed_actor(&pool, archived, "archived").await;
    let res = repo.check_execution_allowed(archived).await;
    assert!(
        res.is_err(),
        "over-budget archived actor must still be refused execution"
    );
    assert_eq!(
        status_of(&pool, archived).await,
        "archived",
        "MCP-646 VIOLATION: budget trip clobbered an archived actor's status"
    );

    // ── Positive control: an ACTIVE actor over budget IS suspended, so the ──
    // ── test can't pass merely because the auto-suspend never fires.       ──
    let active = uuid::Uuid::new_v4();
    seed_actor(&pool, active, "active").await;
    let res = repo.check_execution_allowed(active).await;
    assert!(res.is_err(), "over-budget active actor must be refused");
    assert_eq!(
        status_of(&pool, active).await,
        "suspended",
        "on_budget_exceeded='suspend' must auto-suspend an active actor"
    );
}
