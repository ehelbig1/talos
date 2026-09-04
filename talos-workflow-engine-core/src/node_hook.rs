//! Engine hook for observing node completion.
//!
//! Implementations receive a synchronous notification each time a node
//! produces its final output, before the engine unblocks that node's
//! children. The hook is the engine's extension point for
//! cross-cutting concerns that care about per-node output: cost
//! attribution, side-effect persistence (actor-memory writes, audit
//! ledgers), metrics sampling, etc.
//!
//! The trait is deliberately **sync**. I/O-bearing impls should spawn
//! their own background tasks — this method runs inside the engine's
//! dispatch loop and blocking it would stall every downstream node.

use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Identity + measurements that accompany every node-completion event.
///
/// Passed as a single struct rather than a long parameter list so the
/// call site stays readable and so adding a future field (e.g. fuel
/// consumed, wall-start timestamp) is a non-breaking change for
/// impls — they only pattern-match or field-access what they need.
#[derive(Debug, Clone, Copy)]
pub struct NodeCompletionContext<'a> {
    /// Parent workflow definition id. `Uuid::nil()` when the engine is
    /// running in a context with no durable workflow row (e.g. a
    /// one-off test harness); impls that persist per-workflow rollups
    /// should treat nil as "don't attribute".
    pub workflow_id: Uuid,
    /// Workflow execution that owns this dispatch.
    pub execution_id: Uuid,
    /// Engine-local node identifier within the graph.
    pub node_id: Uuid,
    /// User-defined label for the node (e.g. `"fetch-upcoming"`) when
    /// one exists, or `None` if the node is anonymous. Impls typically
    /// use it for human-readable rollups.
    pub node_label: Option<&'a str>,
    /// Resolved module id the node ran, if the engine has one. `None`
    /// for system nodes that don't dispatch to a wasm module
    /// (`SubWorkflow`, `FanIn`, synthetic triggers, etc.).
    pub module_id: Option<Uuid>,
    /// Actor that owns the execution. Consumers that implement
    /// actor-scoped side effects (for example, an actor-memory write
    /// triggered by an engine protocol field in `output`) key off this.
    pub actor_id: Option<Uuid>,
    /// Data-mutation ceiling in force for this job — the engine's
    /// `max_write_ceiling`, already narrowed for a sub-workflow by
    /// `bind_subengine_actor_and_ceilings`.
    ///
    /// Present because the `__memory_write__` envelope reaches `actor_memory`
    /// through this hook, and until #750 the hook had no way to ask whether
    /// the job's actor was allowed to write: a `readonly` actor was refused at
    /// `agent_memory::set` in the worker and permitted here on the same job.
    /// Impls that persist on the actor's behalf MUST consult it.
    ///
    /// Permissive `Write` is the correct default for the same reason it is the
    /// wire default — an actor-less system job must not be blocked — and the
    /// restrictive default lives at the actor layer.
    pub max_write_ceiling: crate::WriteCeiling,
    /// MONOTONIC execution time in milliseconds, measured from dispatch
    /// to completion with `std::time::Instant` — despite the field name,
    /// which is preserved because it is also the name of the column it
    /// lands in (`execution_cost_rollup.wall_time_ms`). It is a real
    /// duration: a host suspend during the dispatch does not inflate it,
    /// where a `completed_at - started_at` subtraction over the same
    /// interval would. `0` when the engine didn't record a start time
    /// (some legacy paths don't); impls should treat `0` as "unknown"
    /// rather than "instantaneous".
    pub wall_time_ms: u64,
}

/// Called at three points in a node's lifecycle.
///
/// # Contract
///
/// * **Impls that need async I/O MUST `tokio::spawn` (or equivalent).**
///   Every method on this trait runs on the engine's dispatch loop.
///   Awaiting a database write, network call, or any other latency-
///   bearing operation inline will stall every downstream node.
/// * Impls MUST return quickly. Synchronous work MUST be
///   side-effect-only and cheap (e.g. incrementing a counter).
/// * Impls observe output / failure; they do not mutate either.
/// * The engine invokes each method at most once per corresponding
///   lifecycle event: `on_node_completed` on success,
///   `on_node_failed` on terminal node failure,
///   `on_pipeline_step_completed` once per step inside a batch-
///   dispatched chain.
pub trait NodeLifecycleHook: Send + Sync {
    /// Synchronous notification that the node identified by
    /// `ctx.node_id` has produced its final `output`.
    fn on_node_completed(&self, ctx: NodeCompletionContext<'_>, output: &JsonValue);

    /// Synchronous notification that the node failed terminally —
    /// workflow execution is about to abort with an error.
    ///
    /// `error_message` is the human-readable failure reason; `payload`
    /// is the last output the node produced (if any) before failing
    /// — typically the error envelope. Consumers typically use this
    /// to persist a dead-letter-queue row, cancel sibling in-flight
    /// nodes, or emit an audit event.
    ///
    /// Default impl: no-op — consumers that care about failures
    /// override. Not every impl needs failure semantics (metrics-only
    /// impls, test capture hooks, ...).
    fn on_node_failed(
        &self,
        _ctx: NodeCompletionContext<'_>,
        _error_message: &str,
        _payload: Option<&JsonValue>,
    ) {
    }

    /// Synchronous notification that one step of a chain-dispatched
    /// pipeline produced its output. Fires once per step; fires in
    /// addition to `on_node_completed` on the chain head.
    ///
    /// Use this for side effects that must happen per individual
    /// module invocation (e.g. persisting a `__memory_write__`
    /// envelope in the step's output). Do NOT use it for cost
    /// attribution — pipeline fuel is aggregated at the chain level
    /// and billing here would double-count.
    ///
    /// `max_write_ceiling` is the job's data-mutation ceiling. A step's
    /// `__memory_write__` is the same write by the same actor as a node's, so
    /// it obeys the same ceiling; the parameter is explicit rather than
    /// implied so a new impl cannot forget it. See
    /// [`NodeCompletionContext::max_write_ceiling`].
    ///
    /// Default impl: no-op. Consumers without per-step semantics
    /// rely on `on_node_completed` alone.
    fn on_pipeline_step_completed(
        &self,
        _actor_id: Option<Uuid>,
        _step_output: &JsonValue,
        _max_write_ceiling: crate::WriteCeiling,
    ) {
    }

    /// Synchronous notification that a `__memory_write__` envelope was
    /// REFUSED by the write ceiling and dropped by the engine.
    ///
    /// The engine has already removed the envelope from the node output and
    /// stamped
    /// [`reserved_keys::MEMORY_WRITE_REFUSED`](crate::reserved_keys::MEMORY_WRITE_REFUSED)
    /// in its place, so nothing downstream will act on the write or assert it
    /// happened. This method exists so the impl that OWNS the persistence side
    /// effect — and therefore the audit stream, the metric, and the operator
    /// log — can record the refusal, which the engine cannot do (it has no
    /// database, no metrics registry and no audit ledger).
    ///
    /// `key` is the requested memory key, already redacted and length-bounded
    /// by the engine. `node_id` is `None` for a pipeline step, which completes
    /// without its own node identity.
    ///
    /// Default impl: no-op — a metrics-only or test-capture hook need not care.
    fn on_memory_write_refused(
        &self,
        _actor_id: Option<Uuid>,
        _node_id: Option<Uuid>,
        _key: &str,
        _max_write_ceiling: crate::WriteCeiling,
    ) {
    }
}
