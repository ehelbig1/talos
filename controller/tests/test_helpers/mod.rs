use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres as PostgresImage;
use tokio::sync::OnceCell;

/// Shared PostgreSQL container and connection pool for integration tests.
/// The container is started once and reused across all tests in a test binary.
static DB_POOL: OnceCell<Pool<Postgres>> = OnceCell::const_new();
static PG_CONTAINER: OnceCell<ContainerAsync<PostgresImage>> = OnceCell::const_new();

/// Get or initialize the shared test database pool.
/// Starts a PostgreSQL container on first call, runs migrations, and returns the pool.
pub async fn get_test_db_pool() -> Pool<Postgres> {
    DB_POOL
        .get_or_init(|| async {
            // testcontainers-modules ships `postgres:11-alpine` as the
            // hardcoded default tag, but Talos migrations require:
            //   - `gen_random_uuid()` (native to Postgres 13+)
            //   - `vector` extension (third-party pgvector image)
            // Use the same pgvector/pgvector:pg16 digest as
            // docker-compose.yml + the CI services postgres so test,
            // dev, and prod all run the same image.
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

            // Store container to keep it alive
            PG_CONTAINER.get_or_init(|| async { container }).await;

            // Create connection pool
            let pool: Pool<Postgres> = PgPoolOptions::new()
                .max_connections(5)
                .connect(&connection_string)
                .await
                .expect("Failed to connect to test database");

            // Run migrations
            sqlx::migrate!("../migrations")
                .run(&pool)
                .await
                .expect("Failed to run migrations");

            pool
        })
        .await
        .clone()
}
