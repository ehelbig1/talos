//! Controller implementation of [`SubworkflowActorContextResolver`].
//!
//! When the engine is about to dispatch a sub-workflow, it asks this
//! resolver for the `__actor_context__` payload to seed on the freshly-
//! built sub-engine. We look up the sub-workflow's bound `actor_id`
//! from the `workflows` table, then route through the canonical
//! `WorkflowRepository::get_relevant_actor_context` helper — same
//! selection logic (graph RAG → vector similarity → recency, scratchpad
//! filtered) that powers `trigger_workflow`, `test_workflow`, and the
//! scheduler. Single source of truth for actor-context selection across
//! every dispatch path.
//!
//! Returning `None` means "no actor context for this sub-workflow"
//! and the sub-engine runs as it did before this trait existed — the
//! safe pre-trait fallback.

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use std::sync::Arc;
use talos_workflow_engine_core::SubworkflowActorContextResolver;
use uuid::Uuid;

use talos_workflow_repository::WorkflowRepository;

pub struct ControllerSubActorContextResolver {
    workflow_repo: Arc<WorkflowRepository>,
}

impl ControllerSubActorContextResolver {
    pub fn from_repo(workflow_repo: Arc<WorkflowRepository>) -> Self {
        Self { workflow_repo }
    }
}

#[async_trait]
impl SubworkflowActorContextResolver for ControllerSubActorContextResolver {
    async fn resolve(&self, workflow_id: Uuid, user_id: Uuid) -> Option<JsonValue> {
        // Authorization is enforced inside `get_workflow` — it returns
        // `Ok(None)` when `workflow_id` is not visible to `user_id`,
        // which we bubble up as "no context" (correct fail-closed
        // behaviour: a parent that can't see the workflow should
        // certainly not get its context).
        let workflow = self
            .workflow_repo
            .get_workflow(workflow_id, user_id)
            .await
            .ok()
            .flatten()?;

        let actor_id = workflow.actor_id?;

        // Workflow description as the relevance hint — matches what
        // trigger_workflow / scheduler forward, so cross-actor sub-flows
        // pick the same memories that a direct trigger would have picked.
        let memories = self
            .workflow_repo
            .get_relevant_actor_context(actor_id, 20, workflow.description.as_deref())
            .await
            .ok()?;

        if memories.is_empty() {
            return None;
        }

        Some(talos_memory::actor_context::assemble_payload(
            actor_id, &memories,
        ))
    }

    async fn resolve_ceilings(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Option<(
        talos_workflow_engine_core::LlmTier,
        talos_workflow_engine_core::WriteCeiling,
    )> {
        // Same fail-closed authorization posture as `resolve`: `get_workflow`
        // returns `Ok(None)` for a workflow the parent can't see, which we
        // bubble up as `None` (keep the parent's inherited ceiling — the
        // executor never widens, so "unknown" is safe). A sub-workflow with
        // no bound actor also returns `None`.
        let workflow = self
            .workflow_repo
            .get_workflow(workflow_id, user_id)
            .await
            .ok()
            .flatten()?;

        let actor_id = workflow.actor_id?;

        // Tenancy-scoped: get_actor_ceilings returns None if the actor isn't
        // owned by user_id. On DB error we return None (keep the parent
        // ceiling) — the parent ceiling is already the caller's authorized
        // bound, so failing to tighten never escalates.
        self.workflow_repo
            .get_actor_ceilings(actor_id, user_id)
            .await
            .ok()
            .flatten()
    }
}
