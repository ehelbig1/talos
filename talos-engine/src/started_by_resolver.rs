//! Postgres impl of [`talos_workflow_engine_core::StartedByResolver`]: how a
//! top-level run was started, read from its execution row through
//! [`talos_workflow_repository::WorkflowRepository::started_by_of_execution`]
//! (all SQL in the domain crate).
//!
//! Best-effort: a failed read is logged and answered `None`, which leaves
//! `__started_by__` off every node's input. Unknown, never a guess, and never
//! a reason to fail the run.

use async_trait::async_trait;
use sqlx::PgPool;
use talos_workflow_repository::WorkflowRepository;
use uuid::Uuid;

pub struct PostgresStartedByResolver {
    repo: WorkflowRepository,
}

impl PostgresStartedByResolver {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            repo: WorkflowRepository::new(pool),
        }
    }
}

#[async_trait]
impl talos_workflow_engine_core::StartedByResolver for PostgresStartedByResolver {
    async fn started_by_kind(&self, execution_id: Uuid, user_id: Option<Uuid>) -> Option<String> {
        let user_id = user_id?;
        match self
            .repo
            .started_by_of_execution(execution_id, user_id)
            .await
        {
            Ok(found) => found.map(|s| s.kind),
            Err(e) => {
                tracing::warn!(
                    %execution_id,
                    error = %e,
                    "could not read how the run was started; __started_by__ is left off"
                );
                None
            }
        }
    }
}
