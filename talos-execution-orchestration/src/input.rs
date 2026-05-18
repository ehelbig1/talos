//! Input structs for `ExecutionOrchestrationService` methods.
//!
//! Each method takes a single owned struct (matching the
//! `HotUpdateService` / `WorkflowCreationService` convention). New
//! optional fields can be added without touching call sites that
//! don't care, and the input shape is stable enough to be a public
//! API surface for the controller's GraphQL + MCP layers.

use serde_json::Value;
use uuid::Uuid;

/// A single workflow trigger.
///
/// `trigger_input` is the raw JSON payload the workflow receives as
/// its `__trigger__` node output. `trigger_agent_id` overrides the
/// workflow's default `actor_id` for budget + capability ceiling
/// enforcement; falling back to the workflow's stored actor when
/// `None`.
///
/// `inject_memory_context = true` causes the actor's recent
/// memory + scratch context to be merged into `trigger_input` under
/// the canonical `__actor_context__` key before dispatch — opt-in
/// because not every workflow expects the field.
///
/// `wait_ms` is the optional synchronous-wait timeout: when `Some`,
/// the service polls the execution row until it reaches a terminal
/// status or the timeout elapses, then returns the full execution
/// trace in `ExecutionOutcome::trace`. When `None` the service
/// returns immediately after enqueueing the dispatch.
pub struct TriggerInput {
    pub workflow_id: Uuid,
    pub user_id: Uuid,
    pub trigger_input: Value,
    pub trigger_agent_id: Option<Uuid>,
    pub inject_memory_context: bool,
    pub dry_run: bool,
    pub wait_ms: Option<u64>,
}

/// Replay an existing execution with its original trigger input.
///
/// `replay_agent_id` lets the caller override which actor's budget
/// is debited; defaults to the workflow's stored actor when `None`,
/// matching the behaviour for fresh triggers.
pub struct ReplayInput {
    pub original_execution_id: Uuid,
    pub user_id: Uuid,
    pub replay_agent_id: Option<Uuid>,
}

/// Replay with a deep-merged input override. The override is applied
/// recursively over the original trigger input — see `deep_merge` for
/// the exact merge semantics. The caller is responsible for ensuring
/// the override stays under 1 MiB serialised; the service rejects
/// payloads above that with `InvalidArgument`.
pub struct ReplayWithInputInput {
    pub original_execution_id: Uuid,
    pub user_id: Uuid,
    pub replay_agent_id: Option<Uuid>,
    pub input_overrides: Value,
}

/// In-place retry of a `failed` or `cancelled` execution. Unlike
/// `replay`, this does NOT create a new execution row — the original
/// row is reset to `running` and re-dispatched. Provenance chain is
/// unchanged; use `replay` if you want the new run to be linkable to
/// the old one.
pub struct RetryInput {
    pub execution_id: Uuid,
    pub user_id: Uuid,
}
