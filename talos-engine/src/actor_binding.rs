//! Actor → engine binding: the canonical actor-application path.
//!
//! Home of [`apply_actor_to_engine`], moved here from
//! `talos-actor-repository` (2026-07) to fix a layering inversion —
//! the persistence-layer crate depended on `talos-workflow-engine`
//! purely to reach `ParallelWorkflowEngine` for this one function.
//! `talos-engine` is the application layer that already composes the
//! repository and the engine, so the binding lives here.
//!
//! **Security contract (unchanged by the move):** stamps `actor_id`
//! AND the actor's `max_llm_tier` ceiling together, and fail-closes
//! to `Tier1` on DB error or missing actor. Lint check 29 enforces
//! that no consumer calls bare `engine.set_actor_id()` outside this
//! module — a bare call leaves a tier-1 actor at the default Tier-2,
//! a data-egress hole.

use anyhow::Result;
use talos_actor_repository::ActorRepository;
use talos_workflow_engine::ParallelWorkflowEngine;
use talos_workflow_engine_core::LlmTier;
use talos_workflow_engine_core::WriteCeiling;
use uuid::Uuid;

/// Apply the actor context to a workflow engine: sets `actor_id`
/// AND stamps the actor's `max_llm_tier` ceiling. Call this instead
/// of bare `engine.set_actor_id()` so controller callers can't
/// forget the tier stamp and accidentally let a sensitive actor
/// reach external LLMs.
///
/// **Fail-closed on DB error:** if the tier lookup fails (network
/// blip, pool exhaustion, row-locked), we stamp `Tier1` and return
/// `Err` so the caller can decide whether to abort the dispatch.
/// Reverting to Tier2 on a transient Postgres error would silently
/// route a sensitive actor's data to Anthropic — NOT acceptable for
/// a privacy ceiling.
pub async fn apply_actor_to_engine(
    repo: &ActorRepository,
    engine: &mut ParallelWorkflowEngine,
    actor_id: Uuid,
) -> Result<()> {
    engine.set_actor_id(actor_id);
    let tier = match repo.get_actor_max_llm_tier(actor_id).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            // Actor doesn't exist — caller should have verified
            // ownership. Treat as fail-closed so a race (actor
            // deleted between ownership check and dispatch) doesn't
            // escalate to Tier2.
            tracing::warn!(
                %actor_id,
                "apply_actor_to_engine: actor not found; stamping Tier1 and erroring"
            );
            engine.set_max_llm_tier(LlmTier::Tier1);
            return Err(anyhow::anyhow!(
                "actor {actor_id} not found when resolving tier ceiling"
            ));
        }
        Err(e) => {
            // DB error — fail-closed to Tier1 and surface the error.
            // Caller typically logs + aborts the dispatch; the
            // conservative tier stamp defends if the caller proceeds.
            tracing::error!(
                %actor_id,
                error = %e,
                "apply_actor_to_engine: DB error resolving tier; stamping Tier1 and erroring"
            );
            engine.set_max_llm_tier(LlmTier::Tier1);
            return Err(e.context("apply_actor_to_engine: failed to resolve actor tier ceiling"));
        }
    };
    engine.set_max_llm_tier(tier);

    // Data-mutation ceiling — same fail-closed contract as the tier above,
    // but fail-closed to `ReadOnly` (refuse mutation) rather than Tier1.
    // New actors resolve to `ReadOnly` (the migration's column default), so a
    // freshly-built workflow can't mutate data until an operator grants write.
    let ceiling = match repo.get_actor_max_write_ceiling(actor_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            tracing::warn!(
                %actor_id,
                "apply_actor_to_engine: actor not found; stamping ReadOnly and erroring"
            );
            engine.set_max_write_ceiling(WriteCeiling::ReadOnly);
            return Err(anyhow::anyhow!(
                "actor {actor_id} not found when resolving write ceiling"
            ));
        }
        Err(e) => {
            tracing::error!(
                %actor_id,
                error = %e,
                "apply_actor_to_engine: DB error resolving write ceiling; stamping ReadOnly and erroring"
            );
            engine.set_max_write_ceiling(WriteCeiling::ReadOnly);
            return Err(e.context("apply_actor_to_engine: failed to resolve actor write ceiling"));
        }
    };
    engine.set_max_write_ceiling(ceiling);
    Ok(())
}
