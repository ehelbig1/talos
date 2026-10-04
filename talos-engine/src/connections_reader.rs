//! Postgres impl of [`talos_workflow_engine_core::ConnectionsReader`] — the
//! read port behind the `connections` system node.
//!
//! Thin adapter over [`talos_integrations::connections::list_rendered`], the
//! one listing the `list_connections` tool also uses, so a workflow and an
//! author are told the same thing.
//!
//! Tenancy: every query is scoped by the `user_id` the engine passes in,
//! which is the execution's resolved identity.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value as JsonValue};
use sqlx::PgPool;
use talos_secrets_manager::SecretsManager;
use uuid::Uuid;

pub struct PostgresConnectionsReader {
    pool: PgPool,
    secrets: Arc<SecretsManager>,
}

impl PostgresConnectionsReader {
    #[must_use]
    pub fn new(pool: PgPool, secrets: Arc<SecretsManager>) -> Self {
        Self { pool, secrets }
    }
}

#[async_trait]
impl talos_workflow_engine_core::ConnectionsReader for PostgresConnectionsReader {
    async fn connections(
        &self,
        user_id: Uuid,
        provider: Option<&str>,
    ) -> Result<JsonValue, talos_workflow_engine_core::BoxError> {
        let listed = talos_integrations::connections::list_rendered(
            &self.pool,
            &self.secrets,
            user_id,
            provider,
        )
        .await?;
        Ok(json!({
            "count": listed.connections.len(),
            "truncated": listed.truncated,
            "stored_checked": listed.stored_checked,
            "connections": listed.connections,
        }))
    }
}
