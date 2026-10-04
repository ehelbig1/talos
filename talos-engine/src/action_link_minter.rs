//! Postgres impl of [`talos_workflow_engine_core::ActionLinkMinter`] — the
//! mint port behind the `action_links` system node.
//!
//! Thin adapter over
//! [`talos_execution_repository::action_links`] (all SQL stays in the domain
//! crate). Tenancy: every row is written for the `user_id` the engine
//! passes in, which is the execution's resolved identity, and the
//! repository's ownership JOIN refuses any workflow that is not that
//! user's.
//!
//! SECURITY: the minted URLs are capability secrets. They are returned to
//! the engine (which writes them into the node's output — that is the
//! node's purpose) and are never logged here.

use async_trait::async_trait;
use sqlx::PgPool;
use talos_execution_repository::action_links::{action_url, ActionLinkRequest};
use talos_execution_repository::ExecutionRepository;
use talos_workflow_engine_core::action_links::ActionLinkSpec;
use uuid::Uuid;

pub struct PostgresActionLinkMinter {
    repo: ExecutionRepository,
}

impl PostgresActionLinkMinter {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            repo: ExecutionRepository::new(pool),
        }
    }
}

#[async_trait]
impl talos_workflow_engine_core::ActionLinkMinter for PostgresActionLinkMinter {
    async fn mint(
        &self,
        user_id: Uuid,
        source_execution_id: Uuid,
        source_node: &str,
        ttl_hours: Option<u32>,
        specs: &[ActionLinkSpec],
    ) -> Result<Vec<Result<String, String>>, talos_workflow_engine_core::BoxError> {
        let requests: Vec<ActionLinkRequest> = specs
            .iter()
            .map(|spec| ActionLinkRequest {
                workflow_id: spec.workflow_id,
                label: spec.label.clone(),
                payload: spec.payload.clone(),
            })
            .collect();
        let minted = self
            .repo
            .mint_action_tokens(
                user_id,
                Some(source_execution_id),
                Some(source_node),
                ttl_hours.map(i64::from),
                &requests,
            )
            .await?;
        // Resolved per call, like the approval links: a public URL that
        // changed since the last message must not be baked into this one.
        let base_url = talos_public_url::public_base_url_or(talos_config::get_base_url);
        Ok(minted
            .into_iter()
            .map(|outcome| match outcome {
                Ok(raw_token) => Ok(action_url(&base_url, &raw_token)),
                Err(refusal) => Err(refusal.as_str().to_string()),
            })
            .collect())
    }
}
