use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, Connection, PgConnection, Pool, Postgres};
use std::str::FromStr;
use testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres as PostgresImage;
use tokio::sync::OnceCell;

/// Shared PostgreSQL container for integration tests, started once per binary.
/// NOTE: only the *container* is shared — NOT a pool. Each `#[tokio::test]` runs
/// on its own Tokio runtime; sharing one pool across them orphans connections
/// (a pool created in test A's runtime can't do IO once A's runtime is dropped,
/// so a later test hangs acquiring → `PoolTimedOut`). So `get_test_db_pool`
/// hands every caller a FRESH pool, created and dropped within the caller's own
/// runtime. The container + the one-time migration are still amortised globally.
static PG_CONTAINER: OnceCell<ContainerAsync<PostgresImage>> = OnceCell::const_new();
static CONN_STRING: OnceCell<String> = OnceCell::const_new();

/// Start the container (once) + apply migrations (once), returning the shared
/// connection string. The migration pool is closed immediately so it can't leak
/// across runtimes.
async fn shared_conn_string() -> String {
    CONN_STRING
        .get_or_init(|| async {
            // testcontainers-modules ships `postgres:11-alpine` as the
            // hardcoded default tag, but Talos migrations require:
            //   - `gen_random_uuid()` (native to Postgres 13+)
            //   - `vector` extension (third-party pgvector image)
            // Use the same pgvector/pgvector:pg16 image as docker-compose.yml +
            // the CI services postgres so test, dev, and prod run the same image.
            let container = PostgresImage::default()
                .with_name("pgvector/pgvector")
                .with_tag("pg16")
                .start()
                .await
                .expect("Failed to start PostgreSQL container");

            let port = container
                .get_host_port_ipv4(5432)
                .await
                .expect("Failed to get port");
            let connection_string =
                format!("postgres://postgres:postgres@127.0.0.1:{}/postgres", port);

            // Keep the container alive for the whole binary.
            PG_CONTAINER.get_or_init(|| async { container }).await;

            // Apply migrations once, on a throwaway pool that we close right away
            // (don't let it linger across the per-test runtimes).
            let migrate_pool = PgPoolOptions::new()
                .max_connections(2)
                .connect(&connection_string)
                .await
                .expect("Failed to connect for migrations");
            sqlx::migrate!("../migrations")
                .run(&migrate_pool)
                .await
                .expect("Failed to run migrations");
            migrate_pool.close().await;

            connection_string
        })
        .await
        .clone()
}

/// Get a FRESH test database pool against the shared container.
/// Starts the container + runs migrations on first call.
pub async fn get_test_db_pool() -> Pool<Postgres> {
    let connection_string = shared_conn_string().await;
    PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(&connection_string)
        .await
        .expect("Failed to connect to test database")
}

// ─────────────────────────────────────────────────────────────────────────
// Per-test database isolation.
//
// `get_test_db_pool` hands every test the SAME `postgres` database on the
// shared container, so tests that `DELETE FROM modules` and then assert on a
// GLOBAL aggregate (cache size, cache row count) race each other. That is not
// hypothetical: the cache-eviction guards below measure exactly such an
// aggregate, and a peer test wiping the table mid-run can flip them either way
// — including to a vacuous GREEN, which is the worst outcome for a guard.
//
// This gives such a test its own throwaway database, cloned from a migrated
// template that nothing else ever connects to (Postgres refuses to use a
// template that has live connections, which is why the shared `postgres`
// database cannot serve as one). Everything stays inside the ephemeral
// testcontainer, so no cleanup is needed and no non-container database is ever
// touched.
// ─────────────────────────────────────────────────────────────────────────

const TEMPLATE_DB: &str = "talos_isolated_template";

static TEMPLATE_READY: OnceCell<()> = OnceCell::const_new();

/// Create + migrate the clone template exactly once per test binary.
async fn ensure_template(base: &PgConnectOptions) {
    TEMPLATE_READY
        .get_or_init(|| async {
            let mut admin = PgConnection::connect_with(base)
                .await
                .expect("connect to container maintenance db");
            // Idempotent: a re-run inside the same container is fine.
            let _ = sqlx::query(&format!("CREATE DATABASE \"{}\"", TEMPLATE_DB))
                .execute(&mut admin)
                .await;
            let _ = admin.close().await;

            let pool = PgPoolOptions::new()
                .max_connections(2)
                .connect_with(base.clone().database(TEMPLATE_DB))
                .await
                .expect("connect to clone template");
            sqlx::migrate!("../migrations")
                .run(&pool)
                .await
                .expect("migrate clone template");
            // Must be connection-free before it can be used as a TEMPLATE.
            pool.close().await;
        })
        .await;
}

/// A pool on a database of this test's own, cloned from the migrated template.
#[allow(dead_code)]
pub async fn get_isolated_db_pool() -> Pool<Postgres> {
    let base = PgConnectOptions::from_str(&shared_conn_string().await)
        .expect("container connection string is valid")
        .disable_statement_logging();
    ensure_template(&base).await;

    let db_name = format!("t_{}", uuid::Uuid::new_v4().simple());
    let mut admin = PgConnection::connect_with(&base)
        .await
        .expect("connect to container maintenance db");

    // Two tests cloning the same template at the same instant can collide on
    // the "being accessed by other users" window; retry rather than flake.
    let create_sql = format!(
        "CREATE DATABASE \"{}\" TEMPLATE \"{}\"",
        db_name, TEMPLATE_DB
    );
    let mut attempt = 0;
    loop {
        match sqlx::query(&create_sql).execute(&mut admin).await {
            Ok(_) => break,
            Err(e) if attempt < 10 && e.to_string().contains("being accessed by other users") => {
                attempt += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100 * attempt)).await;
            }
            Err(e) => panic!("failed to clone test database: {e}"),
        }
    }
    let _ = admin.close().await;

    PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect_with(base.database(&db_name))
        .await
        .expect("connect to isolated test database")
}
