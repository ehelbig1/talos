//! The controller's answer to "may a child run start as this actor?"
//! (security review 2026-10-14, G-8). See
//! [`talos_workflow_engine_core::ChildRunAdmission`].
//!
//! The actor's hourly FUEL cap, read by
//! [`talos_actor_budget_refusal::child_run_fuel_refusal`] in one statement.
//! A refused child is recorded the way every refused start is
//! ([`talos_actor_budget_refusal::BudgetRefusal::record`]). A read that fails
//! REFUSES: this is a spend gate, and a gate that cannot read its rule does
//! not open.

use async_trait::async_trait;
use talos_workflow_engine_core::ChildRunAdmission;
use uuid::Uuid;

/// The production [`ChildRunAdmission`].
pub struct PostgresChildRunAdmission {
    pool: sqlx::PgPool,
}

impl PostgresChildRunAdmission {
    #[must_use]
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

/// The sentence a child refused because its cap could not be read carries.
pub const CHILD_ADMISSION_UNREADABLE: &str =
    "the actor's fuel budget could not be read, so no sub-workflow run was started";

#[async_trait]
impl ChildRunAdmission for PostgresChildRunAdmission {
    async fn admit_child_run(&self, actor_id: Uuid) -> Result<(), String> {
        match talos_actor_budget_refusal::child_run_fuel_refusal(&self.pool, actor_id).await {
            Ok(None) => Ok(()),
            Ok(Some(refusal)) => {
                tracing::warn!(
                    target: "talos_audit",
                    event_kind = "child_run_refused_fuel_budget",
                    %actor_id,
                    limit = refusal.limit,
                    used = refusal.used,
                    "a sub-workflow run was refused: its actor's hourly fuel cap is spent"
                );
                refusal.record(&self.pool).await;
                Err(refusal.message())
            }
            Err(e) => {
                tracing::error!(
                    %actor_id,
                    error = %e,
                    "child-run admission could not read the actor's fuel budget; refusing"
                );
                Err(CHILD_ADMISSION_UNREADABLE.to_string())
            }
        }
    }
}
