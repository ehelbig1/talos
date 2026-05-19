//! One-shot engine-construction helpers for unit tests.
//!
//! [`minimal_engine`] wires every required adapter with an in-memory
//! or no-op impl so a test can go from zero to "ready to dispatch" in
//! one call. Useful when the test cares about engine behavior, not
//! adapter behavior.
//!
//! Every adapter wired here is independently overridable via the
//! engine's public `set_*` methods after the builder returns.

use std::sync::Arc;

use talos_workflow_engine::ParallelWorkflowEngine;

use crate::approval::AlwaysApproveGate;
use crate::capture::{CaptureEventSink, CaptureModuleExecutionStore, CaptureNodeLifecycleHook};
use crate::memory::{InMemoryModuleFetcher, InMemorySecretsResolver, InMemoryWorkflowGraphStore};
use crate::noop::{
    EverythingTransientClassifier, PassthroughExecutionSanitizer, PassthroughSanitizer,
    StubExpressionEvaluator,
};

/// Build a `ParallelWorkflowEngine` with every adapter wired to an
/// in-memory / no-op default. Intended for unit tests and
/// experimentation — not for production use.
///
/// Disables the filesystem sandbox by default
/// ([`ParallelWorkflowEngine::set_sandbox_root`]`(None)`) so tests run
/// on read-only filesystems, Windows, and sandboxed CI containers
/// without platform-specific setup.
///
/// Wires in this exact set of stubs:
///
/// | Slot | Stub |
/// |---|---|
/// | `SecretsResolver` | [`InMemorySecretsResolver`] — empty map |
/// | `WorkflowGraphStore` | [`InMemoryWorkflowGraphStore`] — empty |
/// | `ModuleFetcher` | [`InMemoryModuleFetcher`] — empty |
/// | `EventSink` | [`CaptureEventSink`] — records every event |
/// | `NodeLifecycleHook` | [`CaptureNodeLifecycleHook`] |
/// | `ModuleExecutionStore` | [`CaptureModuleExecutionStore`] |
/// | `ApprovalGate` | [`AlwaysApproveGate`] |
/// | `OutputSanitizer` | [`PassthroughSanitizer`] |
/// | `ExpressionEvaluator` | [`StubExpressionEvaluator`] — always `true` |
/// | `RetryClassifier` | [`EverythingTransientClassifier`] |
///
/// To customize one adapter, call the engine's `set_*` method after
/// construction:
///
/// ```
/// use std::sync::Arc;
/// use talos_workflow_engine_test_utils::{
///     capture::CaptureNodeLifecycleHook, minimal_engine,
/// };
///
/// let mut engine = minimal_engine();
/// // Override the default hook with one the test can assert against.
/// let hook = Arc::new(CaptureNodeLifecycleHook::new());
/// engine.set_node_hook(hook.clone());
/// ```
#[must_use]
pub fn minimal_engine() -> ParallelWorkflowEngine {
    let mut engine = ParallelWorkflowEngine::new();

    engine.set_secrets_resolver(Arc::new(InMemorySecretsResolver::new()));
    engine.set_graph_store(Arc::new(InMemoryWorkflowGraphStore::new()));
    engine.set_module_fetcher(Arc::new(InMemoryModuleFetcher::new()));
    engine.set_event_sink(Arc::new(CaptureEventSink::new()));
    engine.set_node_hook(Arc::new(CaptureNodeLifecycleHook::new()));
    engine.set_module_execution_store(Arc::new(CaptureModuleExecutionStore::new()));
    engine.set_approval_gate(Arc::new(AlwaysApproveGate));
    engine.set_output_sanitizer(Arc::new(PassthroughSanitizer));
    engine.set_expression_evaluator(Arc::new(StubExpressionEvaluator::new().with_bool(true)));
    engine.set_retry_classifier(Arc::new(EverythingTransientClassifier));

    // Disable the filesystem sandbox by default — tests should not
    // depend on `/tmp` layout, and most test harnesses have no need
    // for per-execution scratch directories.
    engine.set_sandbox_root(None);

    // Silence the "unused" warning on the passthrough execution
    // sanitizer import: the engine does not wire a dedicated
    // execution-scoped sanitizer slot, but the type is re-exported
    // from `noop` so downstream tests can build one if they want to.
    let _ = PassthroughExecutionSanitizer;

    engine
}
