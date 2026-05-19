//! Convenience wrappers that bridge a pre-built `NodeDispatcher`
//! (typically a [`NatsNodeDispatcher`](crate::NatsNodeDispatcher)
//! wrapping a [`NatsTransport`](crate::NatsTransport)) to the engine's
//! abstract `run_with_transport` / `run_with_seed_with_transport`
//! entry points.
//!
//! These exist purely as thin forwards — they let callers import a
//! single "run the engine over NATS" symbol from this crate instead of
//! reaching into `talos_workflow_engine::ParallelWorkflowEngine` directly.
//! Callers that already hold the engine + dispatcher can call
//! `engine.run_with_transport(...)` themselves and ignore this module.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value as JsonValue;
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowEngineError};
use talos_workflow_engine_core::{NodeDispatcher, WorkerSharedKey, WorkflowContext};
use uuid::Uuid;

/// Dispatch the engine via a pre-built `NodeDispatcher`. The usual
/// caller builds a [`NatsNodeDispatcher`](crate::NatsNodeDispatcher)
/// wrapping a [`NatsTransport`](crate::NatsTransport); both live in
/// this crate.
///
/// # Errors
///
/// Forwards the typed [`WorkflowEngineError`] from
/// [`ParallelWorkflowEngine::run_with_transport`].
pub async fn run_with_nats(
    engine: &ParallelWorkflowEngine,
    dispatcher: Arc<dyn NodeDispatcher>,
    worker_shared_key: Option<WorkerSharedKey>,
    execution_id: Uuid,
) -> Result<WorkflowContext, WorkflowEngineError> {
    engine
        .run_with_transport(dispatcher, worker_shared_key, execution_id)
        .await
}

/// Seeded-dispatch variant. Signature mirrors
/// [`ParallelWorkflowEngine::run_with_seed_with_transport`]; the only
/// thing added over a direct call is naming symmetry with
/// [`run_with_nats`].
///
/// # Errors
///
/// Forwards the typed [`WorkflowEngineError`] from
/// [`ParallelWorkflowEngine::run_with_seed_with_transport`].
pub fn run_with_seed_via_nats(
    engine: &ParallelWorkflowEngine,
    dispatcher: Arc<dyn NodeDispatcher>,
    worker_shared_key: Option<WorkerSharedKey>,
    initial_results: HashMap<Uuid, JsonValue>,
    execution_id: Uuid,
) -> Pin<Box<dyn Future<Output = Result<WorkflowContext, WorkflowEngineError>> + Send + '_>> {
    engine.run_with_seed_with_transport(
        dispatcher,
        worker_shared_key,
        initial_results,
        execution_id,
    )
}
