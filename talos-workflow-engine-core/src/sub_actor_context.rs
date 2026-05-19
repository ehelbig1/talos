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
}
