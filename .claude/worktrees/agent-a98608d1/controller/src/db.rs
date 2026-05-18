// WorkflowRecord is defined for future migrations but not currently used.
#![allow(dead_code)]
use anyhow::Context;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WorkflowRecord {
    pub id: Uuid,
    pub name: String,
    pub module_uri: String,
    pub graph_json: String,
}

/// Initialize database connection pool
pub async fn init_pool() -> anyhow::Result<Pool<Postgres>> {
    let _ = dotenvy::dotenv();

    // In production we require an explicit DATABASE_URL; fail fast if it's missing.
    // Load DATABASE_URL or return a clear error instead of panicking.
    let db_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            return Err(anyhow::anyhow!(
                "environment variable DATABASE_URL must be set (Postgres connection string)"
            ));
        }
    };

    // Connection pool configuration for production workloads
    // 30 connections balances performance with resource usage
    let max_connections = std::env::var("DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(30);

    PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(5) // Keep minimum connections warm
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(Some(std::time::Duration::from_secs(300))) // 5 minutes
        .test_before_acquire(true)
        .max_lifetime(Some(std::time::Duration::from_secs(1800))) // 30 minutes
        .connect(&db_url)
        .await
        .context("Failed to connect to Postgres")
}

/// Get a workflow by ID
pub async fn get_workflow(pool: &Pool<Postgres>, id: Uuid) -> anyhow::Result<WorkflowRecord> {
    sqlx::query_as::<_, WorkflowRecord>(
        "SELECT id, name, module_uri, graph_json FROM workflows WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .with_context(|| format!("Workflow {} not found", id))
}
