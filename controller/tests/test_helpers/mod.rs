use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
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
