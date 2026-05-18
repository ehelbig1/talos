//! `PolicyPrePublishHook` trait — the abstraction that `publish_version`
//! uses to consult actor-policy enforcement before committing.
//!
//! Pulled out of `controller::actor_policies::evaluator` so downstream
//! crates (`talos-workflow-versions` and any other publish-time gate)
//! can depend on the abstraction without dragging in the evaluator's
//! transitive deps (rhai, the policy cache, the actor + advanced
//! repositories).
//!
//! `controller::actor_policies::PolicyEvaluator` continues to provide
//! the concrete impl.

use sqlx::{Postgres, Transaction};
use talos_actor_types::PolicyVerdict;
use uuid::Uuid;

#[async_trait::async_trait]
pub trait PolicyPrePublishHook: Send + Sync {
    /// Inspect the candidate publish inside the caller's transaction.
    ///
    /// Implementations must NOT commit `tx`; the caller owns commit and
    /// rollback. Returning `PolicyVerdict::Blocked` aborts publish.
    async fn check(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        actor_id: Uuid,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> anyhow::Result<PolicyVerdict>;
}
