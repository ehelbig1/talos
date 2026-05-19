//! Fluent builder for [`ParallelWorkflowEngine`].
//!
//! The engine has 15+ optional adapter slots and ~10 tunable limit
//! fields. The struct-literal route (`ParallelWorkflowEngine::new()`
//! followed by 8–12 `engine.set_*()` calls) works but reads
//! line-by-line; the builder presents the same shape as one chained
//! expression that's easier to scan and easier to commit to memory.
//!
//! The builder is **purely ergonomic** — it doesn't add any
//! validation the engine's run-path doesn't already do.
//! [`build`](ParallelWorkflowEngineBuilder::build) is infallible.
//! Missing required adapters are caught at run time by
//! [`ParallelWorkflowEngine::run_with_transport`]'s precheck (see
//! [`crate::WorkflowEngineError::SecretsResolverMissing`],
//! [`crate::WorkflowEngineError::ModuleFetcherMissing`],
//! [`crate::WorkflowEngineError::UserContextRequired`]). Use the
//! builder for setup readability; rely on the existing typed errors
//! for misconfiguration.
//!
//! # Example
//!
//! ```
//! # use std::sync::Arc;
//! # use std::time::Duration;
//! # use uuid::Uuid;
//! # use talos_workflow_engine::ParallelWorkflowEngine;
//! # use talos_workflow_engine_test_utils::memory::InMemorySecretsResolver;
//! let engine = ParallelWorkflowEngine::builder()
//!     .with_secrets_resolver(Arc::new(InMemorySecretsResolver::new()))
//!     .with_user_id(Uuid::new_v4())
//!     .with_execution_timeout(Some(Duration::from_secs(60)))
//!     .with_max_workflow_nodes(1000)
//!     .build();
//! ```

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::engine::ParallelWorkflowEngine;

/// Fluent builder for [`ParallelWorkflowEngine`]. Constructed via
/// [`ParallelWorkflowEngine::builder`].
///
/// Every setter returns `Self` so calls chain. [`build`](Self::build)
/// is infallible — the engine's run-path enforces the required-
/// adapter contract via typed [`crate::WorkflowEngineError`]
/// variants (see the module-level docs).
#[derive(Default)]
#[must_use]
pub struct ParallelWorkflowEngineBuilder {
    inner: ParallelWorkflowEngine,
}

impl std::fmt::Debug for ParallelWorkflowEngineBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The inner engine's adapter `Arc<dyn ...>` slots can't
        // reasonably stringify; render only the field counts /
        // primitives that don't leak references.
        f.debug_struct("ParallelWorkflowEngineBuilder")
            .field(
                "execution_timeout_secs",
                &self.inner.execution_timeout_secs(),
            )
            .field("max_workflow_nodes", &self.inner.max_workflow_nodes())
            .field("max_node_output_bytes", &self.inner.max_node_output_bytes())
            .field("max_fuel_per_node", &self.inner.max_fuel_per_node())
            .field(
                "max_prefetch_successors",
                &self.inner.max_prefetch_successors(),
            )
            .field(
                "agent_loop_max_history",
                &self.inner.agent_loop_max_history(),
            )
            .field("max_subflow_depth", &self.inner.max_subflow_depth())
            .finish()
    }
}

impl ParallelWorkflowEngineBuilder {
    /// Build an empty builder. Equivalent to
    /// [`ParallelWorkflowEngine::builder`].
    pub fn new() -> Self {
        Self::default()
    }

    // ── Identity ──────────────────────────────────────────────────

    /// Set the owning user id. **Required** for any run that
    /// dispatches through a [`ModuleFetcher`](talos_workflow_engine_core::ModuleFetcher).
    pub fn with_user_id(mut self, id: Uuid) -> Self {
        self.inner.set_user_id(id);
        self
    }

    /// Set the actor id that owns this execution.
    pub fn with_actor_id(mut self, id: Uuid) -> Self {
        self.inner.set_actor_id(id);
        self
    }

    /// Set the parent workflow definition id (distinct from
    /// `execution_id`; stable across runs).
    pub fn with_workflow_id(mut self, id: Uuid) -> Self {
        self.inner.set_workflow_id(id);
        self
    }

    /// Inject an actor-memory context blob, surfaced to every node
    /// under the reserved `__actor_context__` key.
    pub fn with_actor_context(mut self, context: JsonValue) -> Self {
        self.inner.set_actor_context(context);
        self
    }

    // ── Required policy adapter ───────────────────────────────────

    /// Wire the [`SecretsResolver`](talos_workflow_engine_core::SecretsResolver).
    /// **Required** — every dispatch encrypts per-node secrets
    /// through it.
    pub fn with_secrets_resolver(
        mut self,
        resolver: Arc<dyn talos_workflow_engine_core::SecretsResolver>,
    ) -> Self {
        self.inner.set_secrets_resolver(resolver);
        self
    }

    // ── Storage / dispatch adapters ───────────────────────────────

    /// Wire the [`ModuleFetcher`](talos_workflow_engine_core::ModuleFetcher)
    /// — required when the loaded graph references module-backed
    /// nodes.
    pub fn with_module_fetcher(
        mut self,
        fetcher: Arc<dyn talos_workflow_engine_core::ModuleFetcher>,
    ) -> Self {
        self.inner.set_module_fetcher(fetcher);
        self
    }

    /// Wire the [`WorkflowGraphStore`](talos_workflow_engine_core::WorkflowGraphStore)
    /// — required for sub-workflow dispatch.
    pub fn with_graph_store(
        mut self,
        store: Arc<dyn talos_workflow_engine_core::WorkflowGraphStore>,
    ) -> Self {
        self.inner.set_graph_store(store);
        self
    }

    /// Wire the [`ModuleExecutionStore`](talos_workflow_engine_core::ModuleExecutionStore).
    pub fn with_module_execution_store(
        mut self,
        store: Arc<dyn talos_workflow_engine_core::ModuleExecutionStore>,
    ) -> Self {
        self.inner.set_module_execution_store(store);
        self
    }

    /// Wire the [`EventSink`](talos_workflow_engine_core::EventSink).
    pub fn with_event_sink(mut self, sink: Arc<dyn talos_workflow_engine_core::EventSink>) -> Self {
        self.inner.set_event_sink(sink);
        self
    }

    /// Wire the [`NodeLifecycleHook`](talos_workflow_engine_core::NodeLifecycleHook).
    pub fn with_node_hook(
        mut self,
        hook: Arc<dyn talos_workflow_engine_core::NodeLifecycleHook>,
    ) -> Self {
        self.inner.set_node_hook(hook);
        self
    }

    /// Wire the [`ApprovalGate`](talos_workflow_engine_core::ApprovalGate).
    pub fn with_approval_gate(
        mut self,
        gate: Arc<dyn talos_workflow_engine_core::ApprovalGate>,
    ) -> Self {
        self.inner.set_approval_gate(gate);
        self
    }

    /// Wire the [`SecretEnvelope`](talos_workflow_engine_core::SecretEnvelope).
    /// Defaults to `AesGcmSecretEnvelope`; override only when the
    /// consumer's wire protocol uses a different sealing scheme.
    pub fn with_secret_envelope(
        mut self,
        envelope: Arc<dyn talos_workflow_engine_core::SecretEnvelope>,
    ) -> Self {
        self.inner.set_secret_envelope(envelope);
        self
    }

    /// Wire the [`RateLimitStore`](talos_workflow_engine_core::RateLimitStore)
    /// — typically Redis-backed for cross-replica metering.
    pub fn with_rate_limit_store(
        mut self,
        store: Arc<dyn talos_workflow_engine_core::RateLimitStore>,
    ) -> Self {
        self.inner.set_rate_limit_store(store);
        self
    }

    // ── Cross-cutting policy ──────────────────────────────────────

    /// Wire the [`ExpressionEvaluator`](talos_workflow_engine_core::ExpressionEvaluator).
    pub fn with_expression_evaluator(
        mut self,
        evaluator: Arc<dyn talos_workflow_engine_core::ExpressionEvaluator>,
    ) -> Self {
        self.inner.set_expression_evaluator(evaluator);
        self
    }

    /// Wire the [`OutputSanitizer`](talos_workflow_engine_core::OutputSanitizer).
    pub fn with_output_sanitizer(
        mut self,
        sanitizer: Arc<dyn talos_workflow_engine_core::OutputSanitizer>,
    ) -> Self {
        self.inner.set_output_sanitizer(sanitizer);
        self
    }

    /// Wire the [`RetryClassifier`](talos_workflow_engine_core::RetryClassifier).
    pub fn with_retry_classifier(
        mut self,
        classifier: Arc<dyn talos_workflow_engine_core::RetryClassifier>,
    ) -> Self {
        self.inner.set_retry_classifier(classifier);
        self
    }

    // ── Lifecycle ─────────────────────────────────────────────────

    /// Persist a [`CancellationToken`](tokio_util::sync::CancellationToken)
    /// the run methods consult. `None` clears any prior token.
    pub fn with_cancellation_token(
        mut self,
        token: Option<tokio_util::sync::CancellationToken>,
    ) -> Self {
        self.inner.set_cancellation_token(token);
        self
    }

    /// Set or disable the workflow-level execution timeout.
    pub fn with_execution_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.inner.set_execution_timeout(timeout);
        self
    }

    /// Enable dry-run mode (workers mock side-effectful calls).
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.inner.set_dry_run(dry_run);
        self
    }

    /// Override the per-execution sandbox root.
    pub fn with_sandbox_root(mut self, root: Option<std::path::PathBuf>) -> Self {
        self.inner.set_sandbox_root(root);
        self
    }

    // ── Resource caps ─────────────────────────────────────────────

    /// Override the max number of nodes per loaded graph.
    pub fn with_max_workflow_nodes(mut self, n: usize) -> Self {
        self.inner.set_max_workflow_nodes(n);
        self
    }

    /// Override the per-node output size guard (bytes).
    pub fn with_max_node_output_bytes(mut self, bytes: usize) -> Self {
        self.inner.set_max_node_output_bytes(bytes);
        self
    }

    /// Override the per-node fuel ceiling.
    pub fn with_max_fuel_per_node(mut self, max_fuel: u64) -> Self {
        self.inner.set_max_fuel_per_node(max_fuel);
        self
    }

    /// Override the speculative-prefetch fan-out cap.
    pub fn with_max_prefetch_successors(mut self, n: usize) -> Self {
        self.inner.set_max_prefetch_successors(n);
        self
    }

    /// Override the agent-loop sliding-window history cap.
    pub fn with_agent_loop_max_history(mut self, max: usize) -> Self {
        self.inner.set_agent_loop_max_history(max);
        self
    }

    /// Override the sub-workflow recursion-depth ceiling.
    pub fn with_max_subflow_depth(mut self, depth: usize) -> Self {
        self.inner.set_max_subflow_depth(depth);
        self
    }

    // ── Terminal ──────────────────────────────────────────────────

    /// Finalize the builder into a [`ParallelWorkflowEngine`].
    /// Infallible — the engine's run-path enforces the required-
    /// adapter contract via typed
    /// [`crate::WorkflowEngineError`] variants.
    #[must_use]
    pub fn build(self) -> ParallelWorkflowEngine {
        self.inner
    }
}

impl ParallelWorkflowEngine {
    /// Start a fluent builder for a [`ParallelWorkflowEngine`].
    /// See the [module-level docs](crate::engine_builder) for the
    /// full chaining example and the build-vs-runtime validation
    /// contract.
    pub fn builder() -> ParallelWorkflowEngineBuilder {
        ParallelWorkflowEngineBuilder::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use talos_workflow_engine_test_utils::memory::InMemorySecretsResolver;

    #[test]
    fn build_with_defaults_matches_new() {
        // The builder with no setters called must produce an engine
        // with the same observable state as `ParallelWorkflowEngine::new()`.
        // Drift here would silently change defaults for any consumer
        // adopting the builder.
        let from_builder = ParallelWorkflowEngine::builder().build();
        let from_new = ParallelWorkflowEngine::new();
        assert_eq!(
            from_builder.execution_timeout_secs(),
            from_new.execution_timeout_secs()
        );
        assert_eq!(
            from_builder.max_workflow_nodes(),
            from_new.max_workflow_nodes()
        );
        assert_eq!(
            from_builder.max_subflow_depth(),
            from_new.max_subflow_depth()
        );
        assert_eq!(from_builder.dry_run(), from_new.dry_run());
    }

    #[test]
    fn chained_setters_produce_expected_state() {
        let user = Uuid::new_v4();
        let engine = ParallelWorkflowEngine::builder()
            .with_secrets_resolver(Arc::new(InMemorySecretsResolver::new()))
            .with_user_id(user)
            .with_execution_timeout(Some(Duration::from_secs(45)))
            .with_max_workflow_nodes(123)
            .with_max_subflow_depth(7)
            .with_dry_run(true)
            .build();
        assert_eq!(engine.execution_timeout_secs(), 45);
        assert_eq!(engine.max_workflow_nodes(), 123);
        assert_eq!(engine.max_subflow_depth(), 7);
        assert!(engine.dry_run());
    }

    #[test]
    fn builder_is_infallible_even_with_no_required_adapters() {
        // Builder doesn't validate — the engine's run-path does.
        // Locks in the documented contract: missing required adapters
        // surface as typed `WorkflowEngineError` variants at
        // dispatch time, not at build time.
        let _engine = ParallelWorkflowEngine::builder().build();
    }
}
