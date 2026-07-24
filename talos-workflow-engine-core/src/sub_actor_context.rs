//! Optional adapter for resolving the actor-context payload of a
//! sub-workflow before dispatch.
//!
//! # Why this exists
//!
//! Sub-workflows are routinely bound to a *different* actor than the
//! parent that dispatches them — that's the entire point of cross-actor
//! orchestration ("CEO consults VPE", "support-tier-1 escalates to
//! support-tier-2"). The dispatcher creates a fresh sub-engine and
//! seeds the trigger input, but it has no built-in way to know which
//! actor's memories should land under `__actor_context__` for the
//! sub-engine — that lookup needs to reach into the consumer's actor
//! memory subsystem, which is outside the engine's concern.
//!
//! Without this adapter, every sub-workflow runs with no
//! `__actor_context__` at all, regardless of how its workflow record
//! is bound. LLM nodes downstream that depend on `INJECT_CONTEXT=true`
//! degrade silently to generic, persona-free output — the cross-actor
//! pattern looks wired but produces output that could have come from
//! any actor.
//!
//! # Why it's its own trait (not a method on `WorkflowGraphStore`)
//!
//! `WorkflowGraphStore` is read-only graph hydration with a clean,
//! well-tested security contract. Reaching into actor memory is a
//! separate datastore + a separate authorization model. Keeping the
//! two concerns split lets consumers without an actor-memory layer
//! (test harnesses, the in-memory runtime, embedded shells) opt out
//! implicitly by simply not wiring a resolver — sub-workflows then
//! run as they did before this trait existed, with no
//! `__actor_context__`.
//!
//! # Security contract
//!
//! Same posture as [`WorkflowGraphStore`]: implementations are the
//! single authority on what context `user_id` may see for
//! `workflow_id`. Returning `Ok(None)` for an unauthorized lookup is
//! correct and indistinguishable from "no actor binding" at this
//! layer — the executor does not re-check authorization on the
//! returned payload.
//!
//! Implementations MUST scope the returned payload to memories the
//! caller is authorized to read. The payload is injected into
//! `<agent_memory>` in downstream LLM prompts where it influences
//! generation — leaking another tenant's memories here is a
//! cross-tenant data exposure.

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// A sub-workflow's resolved binding: the actor identity it should run
/// under (memory scope + action attribution) plus the privilege ceilings
/// it should run at.
///
/// Returned by [`SubworkflowActorContextResolver::resolve_binding`] and
/// applied by the executor to a freshly-built sub-engine. The two axes
/// are deliberately independent:
///
/// * **`actor_id`** — the sub-workflow's OWN bound actor. `Some(id)` → the
///   sub-engine adopts this identity, so direct `agent_memory::get/set`
///   RPCs inside the sub-workflow resolve against the sub-workflow's actor
///   (the identity its `workflows.actor_id` records, and the same actor the
///   `resolve` context-injection path already uses). `None` → identity is
///   unknown (a DB-error fail-closed lookup); the executor keeps the
///   parent's identity — the caller's already-authorized bound — while
///   still applying the fail-closed ceilings below. Adopting the
///   sub-actor's identity is NOT an escalation: the resolver only returns
///   a binding for a workflow visible to `user_id` bound to an actor owned
///   by `user_id` (owner-validated, same gate as `resolve`).
/// * **`max_llm_tier` / `max_write_ceiling` / `egress_scope`** — the
///   sub-actor's RAW ceilings. The executor composes these with the
///   parent's as `most_restrictive(parent, sub)` on each axis — a
///   one-directional narrowing that can never widen the sub-workflow's
///   authority.
#[derive(Debug, Clone, Copy)]
pub struct SubworkflowBinding {
    /// The sub-workflow's own bound actor, or `None` when the identity
    /// couldn't be resolved (fail-closed DB error) — see the type docs.
    pub actor_id: Option<Uuid>,
    /// The sub-actor's LLM tier ceiling (data-egress). The executor composes
    /// it with the parent's as `most_restrictive` — never widened.
    pub max_llm_tier: crate::LlmTier,
    /// The sub-actor's write ceiling (mutation authority). Composed with the
    /// parent's as `most_restrictive` — never widened.
    pub max_write_ceiling: crate::WriteCeiling,
    /// The sub-actor's blanket public-egress override (`None` = tier-derived
    /// default). Composed with the parent's via `EgressScope::narrow` —
    /// explicit `Local` on either side wins.
    pub egress_scope: Option<crate::EgressScope>,
}

/// Resolve the `__actor_context__` payload for a sub-workflow about
/// to be dispatched. Returns `None` when the workflow has no actor
/// binding, the actor has no memories worth injecting, or the
/// implementation declines the lookup (auth failure, store error).
#[async_trait]
pub trait SubworkflowActorContextResolver: Send + Sync {
    /// Resolve the actor-context payload for `workflow_id`, scoped to
    /// the parent execution's `user_id`. Returning `None` is the
    /// safe default — it means "do not inject a context for this
    /// sub-workflow", which is identical to the pre-trait behaviour.
    async fn resolve(&self, workflow_id: Uuid, user_id: Uuid) -> Option<JsonValue>;

    /// Resolve the sub-workflow's bound actor identity AND privilege
    /// ceilings in one lookup, scoped to `user_id`.
    ///
    /// The executor uses the result to (a) run the sub-workflow under its
    /// OWN actor's memory scope (so direct `agent_memory` RPCs agree with
    /// the `resolve` context-injection path — see [`SubworkflowBinding`]),
    /// and (b) run at the *more restrictive* of
    /// `(parent_ceiling, sub_actor_ceiling)` on each ceiling axis — a
    /// sub-workflow bound to a stricter actor (e.g. a Tier-1, read-only
    /// persona) must NOT inherit the parent's looser ceiling. Without
    /// this, `AdapterSet` copies the parent's identity AND ceilings
    /// verbatim into the sub-engine, both silently ignoring the
    /// sub-workflow's own binding.
    ///
    /// The default returns `None`, meaning "no distinct sub-actor binding
    /// known" — the executor then keeps the inherited parent identity and
    /// ceilings unchanged (the pre-trait behaviour). A resolver that CAN
    /// answer SHOULD. Note the ceiling composition is one-directional: it
    /// can only ever *narrow* the sub-workflow, so a LOOSER sub-actor
    /// ceiling than the parent's has no widening effect.
    async fn resolve_binding(
        &self,
        _workflow_id: Uuid,
        _user_id: Uuid,
    ) -> Option<SubworkflowBinding> {
        None
    }
}
