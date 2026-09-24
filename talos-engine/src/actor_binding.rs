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
//! AND the actor's `max_llm_tier` ceiling together (plus the write,
//! egress and capability-world ceilings), and fail-closes
//! to the most restrictive value on every axis on DB error or missing actor. Lint check 29 enforces
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
/// Four axes are stamped together: `max_llm_tier`, `max_write_ceiling`,
/// `egress_scope` — and, since 2026-09-10, `max_capability_world`, so the
/// engine can refuse at DISPATCH a module the trigger-time gate never saw
/// (one reached through a sub-workflow / judge / ensemble child). The
/// world ceiling mirrors `authorize_workflow_trigger`'s rule exactly: the
/// auto-provisioned DEFAULT actor is ceiling-exempt (`None`), every other
/// actor's row value binds. `user_id` is what resolves "is this the
/// user's default actor" (`find_default_actor`).
///
/// **Fail-closed on DB error:** if any lookup fails (network
/// blip, pool exhaustion, row-locked), we stamp the most restrictive
/// value on EVERY axis — `Tier1`, `ReadOnly`, `Local`, and a
/// `minimal-node` world ceiling — and return `Err` so the caller can
/// decide whether to abort the dispatch. Reverting to a permissive value
/// on a transient Postgres error would silently route a sensitive actor's
/// data to Anthropic, or run a module above its ceiling — NOT acceptable
/// for a privacy / capability ceiling.
pub async fn apply_actor_to_engine(
    repo: &ActorRepository,
    engine: &mut ParallelWorkflowEngine,
    actor_id: Uuid,
    user_id: Uuid,
) -> Result<()> {
    engine.set_actor_id(actor_id);

    // ONE routine stamps the fail-closed posture on all four axes, so no
    // early-return path below can leave one axis at its permissive default.
    fn stamp_most_restrictive(engine: &mut ParallelWorkflowEngine) {
        engine.set_max_llm_tier(LlmTier::Tier1);
        engine.set_max_write_ceiling(WriteCeiling::ReadOnly);
        // EXPLICIT `ReadOnly`, not `None`. `None` would be restrictive only
        // because the ceiling above it is — a coincidence that stops holding
        // the moment this fail-closed stamp is edited. Every axis says the
        // restrictive thing outright, which is this routine's contract.
        engine.set_http_verb_ceiling(Some(WriteCeiling::ReadOnly));
        engine.set_egress_scope(Some(talos_workflow_engine_core::EgressScope::Local));
        engine.set_max_capability_world(Some(MOST_RESTRICTIVE_WORLD.to_string()));
    }

    // Resolve the three ceilings in ONE row read (was three sequential
    // single-column SELECTs — a per-dispatch latency regression a perf review
    // caught). The fail-closed contract: on actor-not-found or DB error we
    // stamp the MOST restrictive value on every axis and return `Err` so the
    // caller can abort. Reverting any axis to its permissive default on a
    // transient Postgres blip would silently escalate a sensitive actor's
    // authority, which is never acceptable for a privacy/mutation ceiling.
    let (tier, ceiling, egress, http_verb_ceiling) = match repo.get_actor_ceilings(actor_id).await {
        Ok(Some(triple)) => triple,
        Ok(None) => {
            // Actor doesn't exist — caller should have verified ownership.
            // Treat as fail-closed so a race (actor deleted between the
            // ownership check and dispatch) can't escalate any ceiling.
            tracing::warn!(
                %actor_id,
                "apply_actor_to_engine: actor not found; stamping most-restrictive ceilings and erroring"
            );
            stamp_most_restrictive(engine);
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
            stamp_most_restrictive(engine);
            return Err(e.context("apply_actor_to_engine: failed to resolve actor ceilings"));
        }
    };

    // Capability-world ceiling. Two reads rather than one because
    // `get_actor_ceilings` (talos-actor-repository) does not project
    // `max_capability_world` / `is_default`; folding them into that row read
    // is the recorded follow-up. Both are PK / indexed lookups.
    let world = match resolve_world_ceiling(repo, actor_id, user_id).await {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(
                %actor_id,
                error = %e,
                "apply_actor_to_engine: DB error resolving capability ceiling; stamping most-restrictive ceilings and erroring"
            );
            stamp_most_restrictive(engine);
            return Err(e.context("apply_actor_to_engine: failed to resolve capability ceiling"));
        }
    };

    engine.set_max_llm_tier(tier);
    engine.set_max_write_ceiling(ceiling);
    // The verb-inference override travels with the ceiling it modifies. `None`
    // (SQL NULL, every actor that has not been given one) inherits the ceiling
    // above, so this is inert by default.
    engine.set_http_verb_ceiling(http_verb_ceiling);
    // Blanket network-egress scope override — independent of the LLM tier.
    // `None` (SQL NULL, the default for every actor) preserves the tier-derived
    // default at the worker; an explicit `local`/`public` overrides only the
    // blanket public-egress SSRF gate.
    engine.set_egress_scope(egress);
    engine.set_max_capability_world(world);
    Ok(())
}

/// The bottom of the capability lattice — what a fail-closed stamp uses.
const MOST_RESTRICTIVE_WORLD: &str = "minimal-node";

/// The engine's capability-world ceiling for `actor_id`, by the SAME rule
/// `talos_workflow_authorization::authorize_workflow_trigger` applies at
/// trigger time:
///
/// * the user's auto-provisioned DEFAULT actor is ceiling-EXEMPT → `None`
///   (it is an identity/budget/tier bucket, not a capability sandbox — the
///   module's own compiled world, enforced by the worker, is its bound);
/// * any other actor → its `max_capability_world` row value;
/// * no such actor row → the most restrictive world (fail closed; the
///   caller has already erred on the ceilings read for the same reason).
///
/// `Err` is a read failure and the caller stamps fail-closed.
async fn resolve_world_ceiling(
    repo: &ActorRepository,
    actor_id: Uuid,
    user_id: Uuid,
) -> Result<Option<String>> {
    if repo.find_default_actor(user_id).await? == Some(actor_id) {
        return Ok(None);
    }
    Ok(Some(
        repo.try_get_actor_max_world(actor_id)
            .await?
            .unwrap_or_else(|| MOST_RESTRICTIVE_WORLD.to_string()),
    ))
}

#[cfg(test)]
mod fail_closed_axis_pins {
    /// The fail-closed stamp must say the restrictive thing on EVERY axis,
    /// including the verb-inference override.
    ///
    /// `None` there would be restrictive only *because* the ceiling stamped
    /// beside it is `ReadOnly` — a coincidence, and one that stops holding the
    /// moment that line is edited. Measured: changing the stamp to `None`
    /// survived the whole engine + core + worker suite, because no test drives
    /// `apply_actor_to_engine`'s DB-error path (it needs a live repository).
    ///
    /// TEXTUAL, and it says so: it proves the restrictive value is WRITTEN, not
    /// that the function reaches it.
    #[test]
    fn the_fail_closed_stamp_is_explicit_on_the_verb_axis() {
        let src = include_str!("actor_binding.rs");
        // Assembled so this test cannot match its own source.
        let setter = format!("set_http_verb_{}(", "ceiling");
        let restrictive = format!("Some(WriteCeiling::{})", "ReadOnly");

        let body = src
            .split("fn stamp_most_restrictive(")
            .nth(1)
            .expect("the fail-closed stamp routine has been renamed or removed");
        let block = &body[..body.find("\n    }").unwrap_or(body.len())];

        assert!(
            block.contains(&setter),
            "the fail-closed stamp no longer touches the verb-inference axis, \
             so a DB error leaves it INHERITING: {block}"
        );
        assert!(
            block.contains(&restrictive),
            "the fail-closed stamp must write an EXPLICIT ReadOnly on the verb \
             axis, never `None` (inherit): {block}"
        );
    }
}
