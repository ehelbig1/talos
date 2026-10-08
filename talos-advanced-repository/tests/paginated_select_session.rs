// ci-store: selfcontained — scripts/test-integration.sh runs this with that store (scripts/ci_test_targets.py)
//! What the database holds a `query_paginated` statement to, whatever its
//! text says: it cannot change stored data, and what it does to the session
//! it ran on is gone when it returns.
//!
//! The statements here are ones the handler's text rules admit (each begins
//! with SELECT and names nothing on a deny list). They are run through the
//! real `AdvancedRepository::execute_paginated_select`, as the superuser the
//! controller's own pool connects as.
//!
//! Gated on `TALOS_TEST_DATABASE_URL` (any Postgres; needs no migrations).
//! ```sh
//! cargo test -p talos-advanced-repository --test paginated_select_session
//! ```

use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, Pool, Postgres, Row};
use std::time::Duration;
use talos_advanced_repository::{is_read_only_refusal, AdvancedRepository, PaginationMode};
use uuid::Uuid;

fn url() -> Option<String> {
    match std::env::var("TALOS_TEST_DATABASE_URL") {
        Ok(u) if !u.is_empty() => Some(u),
        _ => {
            eprintln!("SKIP: set TALOS_TEST_DATABASE_URL to run paginated_select_session");
            None
        }
    }
}

async fn connect(url: &str, max: u32) -> Pool<Postgres> {
    PgPoolOptions::new()
        .max_connections(max)
        .acquire_timeout(Duration::from_secs(10))
        .connect(url)
        .await
        .expect("connect")
}

/// A schema of this test's own: a sequence, a five-row table, and a function
/// that inserts into it — a stand-in for the volatile functions a real schema
/// carries.
struct Fixture {
    admin: Pool<Postgres>,
    schema: String,
}

impl Fixture {
    async fn new(url: &str) -> Self {
        let admin = connect(url, 2).await;
        let schema = format!("qp_{}", Uuid::new_v4().simple());
        for sql in [
            format!("CREATE SCHEMA {schema}"),
            format!("CREATE SEQUENCE {schema}.seq"),
            format!("CREATE TABLE {schema}.t (id int PRIMARY KEY, label text)"),
            format!("INSERT INTO {schema}.t SELECT g, 'row-' || g FROM generate_series(1, 5) AS g"),
            format!(
                "CREATE FUNCTION {schema}.write_a_row() RETURNS int LANGUAGE plpgsql AS \
                 $$ BEGIN INSERT INTO {schema}.t VALUES (99, 'written'); RETURN 1; END $$"
            ),
        ] {
            admin
                .execute(sqlx::AssertSqlSafe(sql))
                .await
                .expect("fixture");
        }
        Self { admin, schema }
    }

    async fn rows_in_t(&self) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM {}.t",
            self.schema
        )))
        .fetch_one(&self.admin)
        .await
        .expect("count")
    }

    async fn sequence_was_used(&self) -> bool {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT is_called FROM {}.seq",
            self.schema
        )))
        .fetch_one(&self.admin)
        .await
        .expect("sequence state")
    }

    async fn advisory_lock_holders(&self, key: i32) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = $1::oid",
        )
        .bind(i64::from(key))
        .fetch_one(&self.admin)
        .await
        .expect("pg_locks")
    }

    async fn drop(self) {
        let _ = self
            .admin
            .execute(sqlx::AssertSqlSafe(format!(
                "DROP SCHEMA {} CASCADE",
                self.schema
            )))
            .await;
    }
}

const OFFSET_0: PaginationMode<'static> = PaginationMode::Offset { offset: 0 };

fn column<T>(rows: &[sqlx::postgres::PgRow], name: &str) -> Vec<T>
where
    T: for<'r> sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres>,
{
    rows.iter()
        .map(|r| r.try_get(name).expect("column"))
        .collect()
}

async fn backend_pid(pool: &Pool<Postgres>) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(pool)
        .await
        .expect("pid")
}

#[tokio::test]
async fn a_select_that_would_change_stored_data_is_refused_and_changes_nothing() {
    let Some(url) = url() else { return };
    let f = Fixture::new(&url).await;
    let repo = AdvancedRepository::new(connect(&url, 2).await);
    let s = &f.schema;

    for (what, query) in [
        (
            "a function that inserts",
            format!("SELECT {s}.write_a_row() AS v"),
        ),
        (
            "advancing a sequence",
            format!("SELECT nextval('{s}.seq') AS v"),
        ),
        (
            "setting a sequence",
            format!("SELECT setval('{s}.seq', 500) AS v"),
        ),
        ("row locks", format!("SELECT * FROM {s}.t FOR UPDATE")),
    ] {
        let err = repo
            .execute_paginated_select(&query, 10, OFFSET_0)
            .await
            .expect_err(what);
        assert!(is_read_only_refusal(&err), "{what}: {err}");
    }

    // The statement cannot hand itself a read-write transaction first.
    let escape = format!(
        "SELECT set_config('transaction_read_only', 'off', true) AS a, nextval('{s}.seq') AS b"
    );
    repo.execute_paginated_select(&escape, 10, OFFSET_0)
        .await
        .expect_err("switching the transaction to read-write from inside it");

    assert_eq!(f.rows_in_t().await, 5, "a row was written");
    assert!(!f.sequence_was_used().await, "the sequence moved");
    f.drop().await;
}

#[tokio::test]
async fn an_ordinary_select_still_pages_in_both_modes() {
    let Some(url) = url() else { return };
    let f = Fixture::new(&url).await;
    let repo = AdvancedRepository::new(connect(&url, 2).await);
    let base = format!("SELECT id, label FROM {}.t ORDER BY id", f.schema);

    // One row more than the page, which is how the handler learns there is more.
    let page = repo
        .execute_paginated_select(&base, 2, OFFSET_0)
        .await
        .expect("first page");
    let ids = column::<i32>(&page, "id");
    assert_eq!(ids, [1, 2, 3]);

    let page = repo
        .execute_paginated_select(&base, 2, PaginationMode::Offset { offset: 4 })
        .await
        .expect("last page");
    let ids = column::<i32>(&page, "id");
    assert_eq!(ids, [5]);

    let page = repo
        .execute_paginated_select(
            &base,
            10,
            PaginationMode::Cursor {
                column: "label",
                after: "row-3",
            },
        )
        .await
        .expect("cursor page");
    let labels = column::<String>(&page, "label");
    assert_eq!(labels, ["row-4", "row-5"]);
    f.drop().await;
}

/// A SELECT can take a session-level advisory lock; neither a read-only
/// transaction nor a rollback releases one. On a pooled connection it would
/// outlive the call, held by whichever request borrowed the connection next.
/// The pool here has ONE connection, so if the call handed its connection
/// back, the pool's next statement would run on that same backend.
#[tokio::test]
async fn what_a_select_does_to_its_session_ends_with_the_call() {
    let Some(url) = url() else { return };
    let f = Fixture::new(&url).await;
    let pool = connect(&url, 1).await;
    let repo = AdvancedRepository::new(pool.clone());
    let before = backend_pid(&pool).await;
    let key = 1 + (Uuid::new_v4().as_u128() % 2_000_000_000) as i32;

    let query = format!(
        "SELECT set_config('default_transaction_read_only', 'on', false) AS a, \
                pg_advisory_lock({key}) IS NULL AS b"
    );
    repo.execute_paginated_select(&query, 10, OFFSET_0)
        .await
        .expect("the statement itself is a read");

    // The backend exits a moment after it is told to.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while f.advisory_lock_holders(key).await != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the advisory lock the statement took is still held"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_ne!(
        backend_pid(&pool).await,
        before,
        "the pool was handed back the connection the statement ran on"
    );
    let read_only: String = sqlx::query_scalar("SHOW default_transaction_read_only")
        .fetch_one(&pool)
        .await
        .expect("show");
    assert_eq!(read_only, "off");
    let in_read_only_tx: String = sqlx::query_scalar("SHOW transaction_read_only")
        .fetch_one(&pool)
        .await
        .expect("show");
    assert_eq!(in_read_only_tx, "off");
    f.drop().await;
}

/// The caller goes away mid-statement (a dropped request). The connection is
/// inside an open read-only transaction with a statement still running; it
/// must not be the one the pool hands out next.
#[tokio::test]
async fn a_call_abandoned_mid_statement_does_not_return_its_connection() {
    let Some(url) = url() else { return };
    let pool = connect(&url, 1).await;
    let repo = AdvancedRepository::new(pool.clone());
    let before = backend_pid(&pool).await;

    let abandoned = tokio::time::timeout(
        Duration::from_millis(400),
        repo.execute_paginated_select("SELECT pg_sleep(2) IS NULL AS v", 10, OFFSET_0),
    )
    .await;
    assert!(
        abandoned.is_err(),
        "the statement was meant to outlast the wait"
    );

    assert_ne!(
        backend_pid(&pool).await,
        before,
        "the pool was handed back a connection abandoned mid-statement"
    );
    let in_read_only_tx: String = sqlx::query_scalar("SHOW transaction_read_only")
        .fetch_one(&pool)
        .await
        .expect("show");
    assert_eq!(in_read_only_tx, "off");
}
