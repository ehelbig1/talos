//! Public error type for the engine's high-level entry points.
//!
//! Internal scheduling code returns `Result<_, String>` because the
//! engine body is large and the legacy convention pre-dates this
//! module. The public surface — [`ParallelWorkflowEngine::run_with_transport`],
//! [`ParallelWorkflowEngine::run_with_seed_with_transport`],
//! graph-loading methods, and the validators — wraps that string in
//! [`WorkflowEngineError`] so callers can match on documented failure
//! categories instead of substring-matching diagnostic text.
//!
//! # Categorized vs catch-all variants
//!
//! Variants split into three buckets:
//!
//! * **Documented failure modes** with no message body or with
//!   structured fields ([`SecretsResolverMissing`], [`GraphCyclic`],
//!   [`Timeout`]) — the engine commits to surfacing exactly these
//!   conditions when they happen, so consumers can branch on the
//!   variant and produce their own diagnostics.
//! * **Wrappers around lower-level errors** ([`GraphJson`], [`Subflow`])
//!   — pass through the typed inner error so callers retain its
//!   structure.
//! * **Catch-alls with a `String` payload** ([`LoadGraph`],
//!   [`Execution`]) — used when an internal site reports a problem
//!   the engine has not yet promoted to a typed variant. The variants
//!   are stable; the message bodies are not. New typed variants land
//!   in additive minor releases as more failure modes get categorized.
//!
//! [`ParallelWorkflowEngine::run_with_transport`]: crate::ParallelWorkflowEngine::run_with_transport
//! [`ParallelWorkflowEngine::run_with_seed_with_transport`]: crate::ParallelWorkflowEngine::run_with_seed_with_transport
//! [`SecretsResolverMissing`]: WorkflowEngineError::SecretsResolverMissing
//! [`GraphCyclic`]: WorkflowEngineError::GraphCyclic
//! [`Timeout`]: WorkflowEngineError::Timeout
//! [`GraphJson`]: WorkflowEngineError::GraphJson
//! [`Subflow`]: WorkflowEngineError::Subflow
//! [`LoadGraph`]: WorkflowEngineError::LoadGraph
//! [`Execution`]: WorkflowEngineError::Execution

use crate::engine::SubflowError;
use crate::graph_json::GraphJsonError;

/// Public error returned from [`ParallelWorkflowEngine`]'s high-level
/// entry points.
///
/// See the [module-level docs](self) for variant categories and
/// stability semantics.
///
/// [`ParallelWorkflowEngine`]: crate::ParallelWorkflowEngine
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WorkflowEngineError {
    /// The engine was constructed without a [`SecretsResolver`] and a
    /// run was attempted.
    ///
    /// Run-paths refuse to proceed without a resolver because every
    /// dispatch site requires one to encrypt per-node secrets; an
    /// unset resolver would silently produce empty-ciphertext
    /// dispatches. Wire one via
    /// [`set_secrets_resolver`](crate::ParallelWorkflowEngine::set_secrets_resolver)
    /// before calling a run method.
    ///
    /// [`SecretsResolver`]: talos_workflow_engine_core::SecretsResolver
    #[error(
        "ParallelWorkflowEngine has no SecretsResolver configured; \
         call `set_secrets_resolver` before invoking a run method"
    )]
    SecretsResolverMissing,

    /// The configured workflow graph contains a cycle.
    #[error("workflow graph contains a cycle")]
    GraphCyclic,

    /// The graph references at least one module-backed node, but the
    /// engine has no [`ModuleFetcher`] wired in.
    ///
    /// Run-paths refuse to proceed because every per-node dispatch
    /// looks up the resolved wasm artifact through the fetcher; an
    /// unset fetcher would surface as a per-node "module not found"
    /// failure on the first dispatch, masking the configuration
    /// mistake. Wire one via
    /// [`set_module_fetcher`](crate::ParallelWorkflowEngine::set_module_fetcher)
    /// before calling a run method, or load a graph that only uses
    /// system nodes (no `module_id` references).
    ///
    /// [`ModuleFetcher`]: talos_workflow_engine_core::ModuleFetcher
    #[error(
        "ParallelWorkflowEngine has module-backed nodes but no ModuleFetcher \
         configured; call `set_module_fetcher` before invoking a run method"
    )]
    ModuleFetcherMissing,

    /// The graph references at least one module-backed node, but the
    /// engine has no `user_id` set.
    ///
    /// Run-paths refuse to proceed because module-artifact resolution
    /// is scoped per-user (cross-tenant isolation) and dispatch sites
    /// hard-fail without a user. Sub-workflow handlers surface the
    /// same condition through [`SubflowError::NoUserId`] —
    /// promoting it here lets fresh dispatches fail fast at the
    /// wrapper boundary before any dispatch happens. Wire one via
    /// [`set_user_id`](crate::ParallelWorkflowEngine::set_user_id).
    #[error(
        "ParallelWorkflowEngine has module-backed nodes but no user_id; \
         call `set_user_id` before invoking a run method"
    )]
    UserContextRequired,

    /// The workflow exceeded its wall-clock execution timeout.
    ///
    /// Surfaced when [`set_execution_timeout`](crate::ParallelWorkflowEngine::set_execution_timeout)
    /// (or its `_secs` shorthand) configured a non-zero cap and the
    /// scheduler reactor failed to drain the graph within that
    /// deadline. `secs` carries the configured cap so callers can
    /// produce specific diagnostics ("workflow exceeded its 60s
    /// deadline") without parsing the message body.
    ///
    /// Per-node timeouts surface differently — those land as
    /// individual node failures, propagated through
    /// [`Execution`](Self::Execution).
    #[error("workflow execution timed out after {secs} seconds")]
    Timeout {
        /// The wall-clock budget the workflow exceeded, in seconds.
        secs: u64,
    },

    /// A sub-workflow dispatch chain exceeded
    /// [`set_max_subflow_depth`](crate::ParallelWorkflowEngine::set_max_subflow_depth).
    ///
    /// Workflows that compose other workflows (`Judge` calling
    /// `Judge`, `Ensemble` whose child runs an `AgentLoop`, etc.)
    /// stack their dispatch depth. Without a cap, a workflow that
    /// transitively references itself — or a sufficiently deep
    /// composition graph — would stack-overflow the reactor's
    /// recursive sub-engine hydration. The default cap of 16 is
    /// well above any hand-authored composition; raise it for
    /// genuinely-deep compositions, lower it as a defence-in-depth
    /// measure for trust-boundary inputs.
    ///
    /// `depth` is the depth that would have been entered (current +
    /// 1); `limit` is the configured ceiling.
    #[error(
        "sub-workflow recursion depth {depth} exceeds the engine's max ({limit}); \
         a workflow likely composes itself transitively"
    )]
    SubflowRecursionLimit {
        /// Depth the dispatch was about to enter (parent depth + 1).
        depth: usize,
        /// Configured ceiling — the value last passed to
        /// `set_max_subflow_depth`, or
        /// [`DEFAULT_MAX_SUBFLOW_DEPTH`](crate::DEFAULT_MAX_SUBFLOW_DEPTH).
        limit: usize,
    },

    /// The caller requested cancellation via the
    /// [`CancellationToken`](tokio_util::sync::CancellationToken)
    /// passed to
    /// [`run_with_transport_cancellable`](crate::ParallelWorkflowEngine::run_with_transport_cancellable)
    /// or
    /// [`run_with_seed_with_transport_cancellable`](crate::ParallelWorkflowEngine::run_with_seed_with_transport_cancellable).
    ///
    /// The engine reactor stops scheduling new dispatches and
    /// returns this variant. **In-flight worker dispatches are not
    /// aborted** — the engine has no out-of-band channel back to a
    /// worker pool; consumer-side cancellation of in-flight wasm is
    /// the dispatcher impl's responsibility (e.g. by carrying the
    /// `DispatchJob::cancellation_token` to the worker over the same
    /// transport). What this variant does promise: the engine itself
    /// stops wasting compute on a workflow the caller has signalled
    /// it no longer wants.
    #[error("workflow execution was cancelled by caller")]
    Cancelled,

    /// Hard structural problem reading a `graph_json` payload —
    /// invalid JSON, top-level not an object, or `nodes` / `edges`
    /// fields with the wrong type. Soft issues (skipped nodes,
    /// unknown system kinds) flow through
    /// [`GraphSummary::warnings`](crate::GraphSummary) instead.
    #[error("graph JSON is malformed: {0}")]
    GraphJson(#[from] GraphJsonError),

    /// Sub-workflow execution failed. Carries the structured
    /// [`SubflowError`] from the engine's sub-workflow dispatch path.
    #[error("sub-workflow execution failed: {0:?}")]
    Subflow(SubflowError),

    /// The graph document parsed cleanly but has no nodes.
    ///
    /// Surfaces from [`load_from_graph_json`] and
    /// [`load_graph_from_json`] when `nodes` is absent or an empty
    /// array. This is a validation failure, not a parse failure —
    /// the document was structurally valid but describes no work to
    /// run. Consumers that batch-load user-authored graphs usually
    /// want to branch on this variant specifically so they can
    /// surface a "your workflow has no steps yet" UX instead of a
    /// generic "load failed".
    ///
    /// [`load_from_graph_json`]: crate::ParallelWorkflowEngine::load_from_graph_json
    /// [`load_graph_from_json`]: crate::ParallelWorkflowEngine::load_graph_from_json
    #[error("workflow graph has no nodes")]
    EmptyGraph,

    /// A graph-loading method rejected its input for a reason the
    /// engine has not yet promoted to a typed variant. The message
    /// body is human-readable; do not pattern-match its text — match
    /// on the variant only.
    #[error("graph load failed: {0}")]
    LoadGraph(String),

    /// A run failed for a reason the engine has not yet promoted to
    /// a typed variant. The message body is human-readable; do not
    /// pattern-match its text — match on the variant only.
    #[error("workflow execution failed: {0}")]
    Execution(String),
}

impl WorkflowEngineError {
    /// Construct an [`Execution`](Self::Execution) variant from any
    /// `Into<String>` source. Convenience for `.map_err` chains:
    ///
    /// ```ignore
    /// some_call().await.map_err(WorkflowEngineError::execution)?;
    /// ```
    pub fn execution(message: impl Into<String>) -> Self {
        Self::Execution(message.into())
    }

    /// Construct a [`LoadGraph`](Self::LoadGraph) variant from any
    /// `Into<String>` source. Convenience for `.map_err` chains.
    pub fn load_graph(message: impl Into<String>) -> Self {
        Self::LoadGraph(message.into())
    }
}

impl From<SubflowError> for WorkflowEngineError {
    fn from(value: SubflowError) -> Self {
        Self::Subflow(value)
    }
}

impl From<crate::graph_builder::BuildError> for WorkflowEngineError {
    /// A [`WorkflowGraphBuilder`](crate::WorkflowGraphBuilder) that
    /// accumulated errors and failed at [`build`](crate::WorkflowGraphBuilder::build)
    /// is semantically a graph-load failure — the builder output is
    /// the exact artifact the engine would have otherwise loaded.
    /// Route through the [`LoadGraph`](Self::LoadGraph) catch-all so
    /// callers using `?` from a builder chain see the same variant
    /// they'd see for any other malformed input.
    fn from(value: crate::graph_builder::BuildError) -> Self {
        Self::LoadGraph(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_constructor_wraps_message() {
        let err = WorkflowEngineError::execution("boom");
        assert!(matches!(err, WorkflowEngineError::Execution(ref s) if s == "boom"));
        assert_eq!(err.to_string(), "workflow execution failed: boom");
    }

    #[test]
    fn load_graph_constructor_wraps_message() {
        let err = WorkflowEngineError::load_graph("missing nodes");
        assert!(matches!(err, WorkflowEngineError::LoadGraph(ref s) if s == "missing nodes"));
    }

    #[test]
    fn secrets_resolver_missing_has_descriptive_display() {
        let err = WorkflowEngineError::SecretsResolverMissing;
        assert!(err.to_string().contains("SecretsResolver"));
    }

    #[test]
    fn graph_cyclic_has_descriptive_display() {
        let err = WorkflowEngineError::GraphCyclic;
        assert_eq!(err.to_string(), "workflow graph contains a cycle");
    }

    #[test]
    fn from_graph_json_error_promotes() {
        let json_err: GraphJsonError = serde_json::from_str::<serde_json::Value>("{not")
            .map_err(GraphJsonError::from)
            .unwrap_err();
        let wrapped: WorkflowEngineError = json_err.into();
        assert!(matches!(wrapped, WorkflowEngineError::GraphJson(_)));
    }

    #[test]
    fn from_subflow_error_promotes() {
        let sub = SubflowError::NoUserId;
        let wrapped: WorkflowEngineError = sub.into();
        assert!(matches!(wrapped, WorkflowEngineError::Subflow(_)));
    }
}
