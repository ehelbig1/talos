//! Postgres-backed integration test for the write-ceiling GRANT guard
//! (migration 20260709180000).
//!
//! The `actors_write_ceiling_grant_guard` trigger blocks any
//! `readonly -> write` escalation unless the session opts in via the
//! transaction-local GUC `talos.allow_ceiling_grant`. Only
//! `ActorRepository::set_actor_max_write_ceiling` sets that GUC, so a
//! bulk / migration-re-run `UPDATE actors SET max_write_ceiling='write'`
//! (the grandfather footgun) is refused, while the sanctioned operator
//! path still works. This pins all three arms end-to-end against a real
//! trigger so a regression in either the trigger or the GUC-setting repo
//! path fails loudly.
//!
//! Skipped (green) unless `TALOS_TEST_DATABASE_URL` is set. Run locally:
//!
//! ```bash
//! docker run -d --rm -e POSTGRES_PASSWORD=test -e POSTGRES_DB=talos \
//!   -p 15434:5432 postgres:16-alpine
//! TALOS_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:15434/talos \
//!   cargo test -p talos-actor-repository --test write_ceiling_guard_integration
//! ```

use sqlx::{Executor, PgPool, Row};
use talos_actor_repository::ActorRepository;
use talos_workflow_job_protocol::WriteCeiling;

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

/// Minimal `actors` schema + the guard function/trigger, verbatim in spirit
/// from migration 20260709180000. Self-contained so the test doesn't depend
/// on the full migration set.
async fn setup(pool: &PgPool) {
    pool.execute(
        "DROP TABLE IF EXISTS actors CASCADE; \
         CREATE TABLE actors ( \
            id uuid PRIMARY KEY, \
            user_id uuid NOT NULL, \
            name text NOT NULL DEFAULT 'a', \
            max_write_ceiling text NOT NULL DEFAULT 'readonly' \
                CHECK (max_write_ceiling IN ('readonly', 'write')));",
    )
    .await
    .unwrap();

    pool.execute(
        "CREATE OR REPLACE FUNCTION talos_guard_actor_write_ceiling() \
            RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN \
            IF NEW.max_write_ceiling = 'write' \
               AND OLD.max_write_ceiling IS DISTINCT FROM 'write' \
               AND current_setting('talos.allow_ceiling_grant', true) IS DISTINCT FROM 'on' \
            THEN \
                RAISE EXCEPTION 'refusing to grant write ceiling to actor % outside the sanctioned path', NEW.id \
                    USING ERRCODE = 'check_violation'; \
            END IF; \
            RETURN NEW; \
         END; $$; \
         CREATE OR REPLACE TRIGGER actors_write_ceiling_grant_guard \
            BEFORE UPDATE OF max_write_ceiling ON actors \
            FOR EACH ROW EXECUTE FUNCTION talos_guard_actor_write_ceiling();",
    )
    .await
    .unwrap();
}

async fn ceiling_of(pool: &PgPool, id: uuid::Uuid) -> String {
    sqlx::query("SELECT max_write_ceiling FROM actors WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
        .get::<String, _>("max_write_ceiling")
}

#[tokio::test]
async fn guard_blocks_bulk_clobber_but_allows_sanctioned_grant() {
    let pool = pool_or_skip!();
    setup(&pool).await;

    let user = uuid::Uuid::new_v4();
    let actor = uuid::Uuid::new_v4();
    // New actor: column default is readonly (the secure default).
    sqlx::query("INSERT INTO actors (id, user_id) VALUES ($1, $2)")
        .bind(actor)
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(ceiling_of(&pool, actor).await, "readonly");

    // (A) The footgun: an un-guarded bulk escalation to write — exactly what
    //     the grandfather migration's blank UPDATE does on a re-run — MUST be
    //     refused, and the readonly actor MUST survive unchanged.
    let bulk = pool
        .execute("UPDATE actors SET max_write_ceiling = 'write'")
        .await;
    assert!(
        bulk.is_err(),
        "bulk readonly->write with no GUC must be refused by the guard"
    );
    assert_eq!(
        ceiling_of(&pool, actor).await,
        "readonly",
        "the aborted statement must leave the actor read-only"
    );

    // (B) The sanctioned path grants write (it sets the GUC internally).
    let repo = ActorRepository::new(pool.clone());
    let granted = repo
        .set_actor_max_write_ceiling(actor, user, WriteCeiling::Write)
        .await
        .expect("sanctioned grant should not error");
    assert!(granted, "grant should report a row updated");
    assert_eq!(ceiling_of(&pool, actor).await, "write");

    // (C) Locking back down (write->readonly) is always allowed.
    let locked = repo
        .set_actor_max_write_ceiling(actor, user, WriteCeiling::ReadOnly)
        .await
        .expect("lock-down should not error");
    assert!(locked);
    assert_eq!(ceiling_of(&pool, actor).await, "readonly");
}
