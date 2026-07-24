//! Postgres impl of [`talos_workflow_engine_core::OperatorDigestReader`]
//! — the read port behind the `operator_digest` system node (the
//! autonomy-cockpit feed: ran / learned / needs_me over a trailing window).
//!
//! Unlike the `assistant_report` reader (which composes the domain
//! repositories directly), this impl just wraps `talos_operator_digest::
//! OperatorDigestService` — SQL ownership stays inside that domain crate.
//! Tenancy: every query is scoped by the `user_id` the engine passes in
//! (the execution's resolved identity — node config carries no identity).

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresOperatorDigestReader {
    service: talos_operator_digest::OperatorDigestService,
}

impl PostgresOperatorDigestReader {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            service: talos_operator_digest::OperatorDigestService::new(pool),
        }
    }
}

#[async_trait]
impl talos_workflow_engine_core::OperatorDigestReader for PostgresOperatorDigestReader {
    async fn snapshot(
        &self,
        user_id: Uuid,
        days: u32,
    ) -> Result<JsonValue, talos_workflow_engine_core::BoxError> {
        self.service
            .snapshot(user_id, days)
            .await
            .map_err(|e| e.into())
    }
}
