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
        // Fleet-wide kill-switch: skip sub-workflow context assembly entirely
        // when actor-context injection is disabled (the dispatch chokepoints
        // would refuse it anyway — this avoids the wasted lookup).
        if !talos_config::actor_context_injection_enabled() {
            return None;
        }
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
            .get_relevant_actor_context(
                actor_id,
                20,
                workflow.description.as_deref(),
                None,
                // Auto-injection into a sub-workflow → curated scope (secure default).
                talos_workflow_repository::MemoryScope::Curated,
            )
            .await
            .ok()?;

        if memories.is_empty() {
            return None;
        }

        Some(talos_memory::actor_context::assemble_payload(
            actor_id, &memories,
        ))
    }

    async fn resolve_binding(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Option<talos_workflow_engine_core::SubworkflowBinding> {
        // ONE narrow joined query (workflows ⋈ actors, a few small columns, no
        // graph_json, tenancy-scoped on both sides). The first cut called
        // `get_workflow` (full row incl. the graph, in an RLS tx) just for
        // `actor_id` plus a second ceilings query — a per-sub-dispatch double
        // fetch a perf review caught. Now returns identity + ceilings in the
        // same round-trip so the executor can bind both atomically.
        match self
            .workflow_repo
            .get_workflow_actor_binding(workflow_id, user_id)
            .await
        {
            // Workflow visible + actor bound + owned → the real binding.
            // `actor_id` is present so the sub-engine adopts the sub-workflow's
            // OWN memory scope; ceilings are the sub-actor's RAW values (the
            // executor narrows them against the parent).
            Ok(Some((actor_id, tier, write, egress))) => {
                Some(talos_workflow_engine_core::SubworkflowBinding {
                    actor_id: Some(actor_id),
                    max_llm_tier: tier,
                    max_write_ceiling: write,
                    egress_scope: egress,
                })
            }
            // Workflow not visible / no bound actor / actor not owned →
            // `None` keeps the parent's inherited identity + ceilings. Safe:
            // the executor only ever NARROWS ceilings, the parent bound is
            // already the caller's authorized one, and a not-visible workflow
            // fails the graph fetch in lockstep anyway.
            Ok(None) => None,
            // DB error → fail CLOSED to the most-restrictive ceilings rather
            // than `None`-ing back to the parent ceiling. A security review
            // flagged the original `.ok()` here: with the sub-workflow's graph
            // served from the engine's cache, a transient DB error on THIS
            // query was the one path where a stricter sub-actor's bound was
            // silently skipped (fail-open w.r.t. the sub-actor's intent — the
            // same class #503 converted to fail-closed elsewhere). Matches the
            // `apply_actor_to_engine` precedent: on DB error, stamp
            // restrictive. `actor_id: None` — we couldn't resolve the identity,
            // so the executor KEEPS the parent's identity (the caller's
            // authorized bound) rather than guessing a scope; the fail-closed
            // ceilings still apply. Cost: during a DB blip a sub-workflow runs
            // local-only/read-only (and likely fails loudly) instead of
            // running at the looser parent ceiling.
            Err(e) => {
                tracing::error!(
                    target: "talos_security",
                    %workflow_id,
                    error = %e,
                    "resolve_binding: DB error resolving sub-workflow actor binding; \
                     failing closed to (Tier1, ReadOnly), keeping parent identity"
                );
                Some(talos_workflow_engine_core::SubworkflowBinding {
                    actor_id: None,
                    max_llm_tier: talos_workflow_engine_core::LlmTier::Tier1,
                    max_write_ceiling: talos_workflow_engine_core::WriteCeiling::ReadOnly,
                    // Fail closed on the egress axis too: no public egress.
                    egress_scope: Some(talos_workflow_engine_core::EgressScope::Local),
                })
            }
        }
    }
}
