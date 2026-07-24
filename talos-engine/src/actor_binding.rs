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

    // Resolve all three ceilings in ONE row read (was three sequential
    // single-column SELECTs — a per-dispatch latency regression a perf review
    // caught). The fail-closed contract is UNCHANGED: on actor-not-found or DB
    // error we stamp the MOST restrictive value on every axis — `Tier1` (LLM
    // stays local), `ReadOnly` (refuse mutation), `Some(Local)` (no public
    // egress) — and return `Err` so the caller can abort. Reverting any axis to
    // its permissive default on a transient Postgres blip would silently
    // escalate a sensitive actor's authority, which is never acceptable for a
    // privacy/mutation ceiling.
    let (tier, ceiling, egress) = match repo.get_actor_ceilings(actor_id).await {
        Ok(Some(triple)) => triple,
        Ok(None) => {
            // Actor doesn't exist — caller should have verified ownership.
            // Treat as fail-closed so a race (actor deleted between the
            // ownership check and dispatch) can't escalate any ceiling.
            tracing::warn!(
                %actor_id,
                "apply_actor_to_engine: actor not found; stamping most-restrictive ceilings and erroring"
            );
            engine.set_max_llm_tier(LlmTier::Tier1);
            engine.set_max_write_ceiling(WriteCeiling::ReadOnly);
            engine.set_egress_scope(Some(talos_workflow_engine_core::EgressScope::Local));
            return Err(anyhow::anyhow!(
                "actor {actor_id} not found when resolving engine ceilings"
            ));
        }
        Err(e) => {
            tracing::error!(
                %actor_id,
                error = %e,
                "apply_actor_to_engine: DB error resolving ceilings; stamping most-restrictive ceilings and erroring"
            );
            engine.set_max_llm_tier(LlmTier::Tier1);
            engine.set_max_write_ceiling(WriteCeiling::ReadOnly);
            engine.set_egress_scope(Some(talos_workflow_engine_core::EgressScope::Local));
            return Err(e.context("apply_actor_to_engine: failed to resolve actor ceilings"));
        }
    };
    engine.set_max_llm_tier(tier);
    engine.set_max_write_ceiling(ceiling);
    // Blanket network-egress scope override — independent of the LLM tier.
    // `None` (SQL NULL, the default for every actor) preserves the tier-derived
    // default at the worker; an explicit `local`/`public` overrides only the
    // blanket public-egress SSRF gate.
    engine.set_egress_scope(egress);
    Ok(())
}
