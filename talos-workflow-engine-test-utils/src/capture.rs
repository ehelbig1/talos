//! Record-and-assert implementations. Each one stores every call the
//! engine makes into a thread-safe buffer a test can drain at the end.
//!
//! # Concurrency
//!
//! All three capture stores are `Send + Sync` and clone via `Arc`.
//! The engine's fire-and-forget emit path (`tokio::spawn`) may call
//! these from multiple tasks concurrently; the internal locks use
//! `std::sync::Mutex` — reads/writes are non-async and short, so lock
//! contention is not a concern for typical test shapes.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use talos_workflow_engine_core::{
    BoxError, EventSink, ExecutionStartedContext, ModuleExecutionStore, NodeCompletionContext,
    NodeEventWrite, NodeLifecycleHook,
};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// CaptureEventSink
// ─────────────────────────────────────────────────────────────────────────────

/// [`EventSink`] that records every emitted event in a shared `Vec`.
#[derive(Clone, Default)]
pub struct CaptureEventSink {
    events: Arc<Mutex<Vec<NodeEventWrite>>>,
}

impl CaptureEventSink {
    /// Build an empty capture sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of events emitted so far. Returns owned clones so the
    /// caller can iterate / assert without holding the internal lock.
    pub fn events(&self) -> Vec<NodeEventWrite> {
        self.events
            .lock()
            .expect("CaptureEventSink mutex poisoned")
            .clone()
    }

    /// Count of events emitted so far.
    pub fn len(&self) -> usize {
        self.events
            .lock()
            .expect("CaptureEventSink mutex poisoned")
            .len()
    }

    /// True when no events have been emitted.
    pub fn is_empty(&self) -> bool {
        self.events
            .lock()
            .expect("CaptureEventSink mutex poisoned")
            .is_empty()
    }

    /// Filter recorded events by `event_type`. Common in tests that
    /// only care about one category (e.g. `node_failed`).
    pub fn events_of_type(&self, event_type: &str) -> Vec<NodeEventWrite> {
        self.events
            .lock()
            .expect("CaptureEventSink mutex poisoned")
            .iter()
            .filter(|e| e.event_type == event_type)
            .cloned()
            .collect()
    }

    /// Drop all recorded events. Useful between stages of a multi-run
    /// test.
    pub fn clear(&self) {
        self.events
            .lock()
            .expect("CaptureEventSink mutex poisoned")
            .clear();
    }
}

impl std::fmt::Debug for CaptureEventSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureEventSink")
            .field("len", &self.len())
            .finish()
    }
}

#[async_trait]
impl EventSink for CaptureEventSink {
    async fn emit(&self, event: NodeEventWrite) {
        self.events
            .lock()
            .expect("CaptureEventSink mutex poisoned")
            .push(event);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CaptureNodeLifecycleHook
// ─────────────────────────────────────────────────────────────────────────────

/// One captured lifecycle-hook callback.
#[derive(Debug, Clone)]
pub enum LifecycleCall {
    /// `on_node_completed` — `(workflow_id, execution_id, node_id, label, actor_id, module_id, wall_time_ms, output)`.
    Completed {
        /// Parent workflow definition id.
        workflow_id: Uuid,
        /// Workflow execution id.
        execution_id: Uuid,
        /// Engine-local node id.
        node_id: Uuid,
        /// User-defined node label, if any.
        node_label: Option<String>,
        /// Actor owning the execution, if any.
        actor_id: Option<Uuid>,
        /// Resolved module id, if the node dispatches a wasm module.
        module_id: Option<Uuid>,
        /// Wall-clock execution time in ms (`0` = unknown).
        wall_time_ms: u64,
        /// Final node output.
        output: JsonValue,
    },
    /// `on_node_failed` — terminal node failure.
    Failed {
        /// Parent workflow definition id.
        workflow_id: Uuid,
        /// Workflow execution id.
        execution_id: Uuid,
        /// Engine-local node id.
        node_id: Uuid,
        /// User-defined node label, if any.
        node_label: Option<String>,
        /// Actor owning the execution, if any.
        actor_id: Option<Uuid>,
        /// Resolved module id, if the node dispatched a wasm module.
        module_id: Option<Uuid>,
        /// Wall-clock execution time in ms (`0` = unknown).
        wall_time_ms: u64,
        /// Human-readable failure message.
        error_message: String,
        /// Last output the node produced before failing, if any.
        payload: Option<JsonValue>,
    },
    /// `on_pipeline_step_completed` — one successful chain step.
    PipelineStepCompleted {
        /// Actor owning the execution, if any.
        actor_id: Option<Uuid>,
        /// Step output.
        step_output: JsonValue,
    },
}

/// [`NodeLifecycleHook`] that records every lifecycle event as a
/// [`LifecycleCall`] in a shared `Vec`.
#[derive(Clone, Default)]
pub struct CaptureNodeLifecycleHook {
    calls: Arc<Mutex<Vec<LifecycleCall>>>,
}

impl CaptureNodeLifecycleHook {
    /// Build an empty capture hook.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of recorded callbacks.
    pub fn calls(&self) -> Vec<LifecycleCall> {
        self.calls
            .lock()
            .expect("CaptureNodeLifecycleHook mutex poisoned")
            .clone()
    }

    /// Count of recorded callbacks.
    pub fn len(&self) -> usize {
        self.calls
            .lock()
            .expect("CaptureNodeLifecycleHook mutex poisoned")
            .len()
    }

    /// True when no callbacks have fired.
    pub fn is_empty(&self) -> bool {
        self.calls
            .lock()
            .expect("CaptureNodeLifecycleHook mutex poisoned")
            .is_empty()
    }

    /// Drop all recorded callbacks.
    pub fn clear(&self) {
        self.calls
            .lock()
            .expect("CaptureNodeLifecycleHook mutex poisoned")
            .clear();
    }
}

impl std::fmt::Debug for CaptureNodeLifecycleHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureNodeLifecycleHook")
            .field("len", &self.len())
            .finish()
    }
}

impl NodeLifecycleHook for CaptureNodeLifecycleHook {
    fn on_node_completed(&self, ctx: NodeCompletionContext<'_>, output: &JsonValue) {
        self.calls
            .lock()
            .expect("CaptureNodeLifecycleHook mutex poisoned")
            .push(LifecycleCall::Completed {
                workflow_id: ctx.workflow_id,
                execution_id: ctx.execution_id,
                node_id: ctx.node_id,
                node_label: ctx.node_label.map(ToString::to_string),
                actor_id: ctx.actor_id,
                module_id: ctx.module_id,
                wall_time_ms: ctx.wall_time_ms,
                output: output.clone(),
            });
    }

    fn on_node_failed(
        &self,
        ctx: NodeCompletionContext<'_>,
        error_message: &str,
        payload: Option<&JsonValue>,
    ) {
        self.calls
            .lock()
            .expect("CaptureNodeLifecycleHook mutex poisoned")
            .push(LifecycleCall::Failed {
                workflow_id: ctx.workflow_id,
                execution_id: ctx.execution_id,
                node_id: ctx.node_id,
                node_label: ctx.node_label.map(ToString::to_string),
                actor_id: ctx.actor_id,
                module_id: ctx.module_id,
                wall_time_ms: ctx.wall_time_ms,
                error_message: error_message.to_string(),
                payload: payload.cloned(),
            });
    }

    fn on_pipeline_step_completed(&self, actor_id: Option<Uuid>, step_output: &JsonValue) {
        self.calls
            .lock()
            .expect("CaptureNodeLifecycleHook mutex poisoned")
            .push(LifecycleCall::PipelineStepCompleted {
                actor_id,
                step_output: step_output.clone(),
            });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CaptureModuleExecutionStore
// ─────────────────────────────────────────────────────────────────────────────

/// One recorded call against [`CaptureModuleExecutionStore`].
#[derive(Debug, Clone)]
pub enum ExecutionStoreCall {
    /// `record_started` — pre-dispatch row.
    Started {
        /// Row / dispatch id.
        id: Uuid,
        /// Resolved module id.
        module_id: Uuid,
        /// Owning user.
        user_id: Uuid,
        /// Parent workflow execution id.
        workflow_execution_id: Uuid,
        /// Input payload.
        input: JsonValue,
        /// Trigger origin (`"webhook"`, `"scheduled"`, ...).
        trigger_type: String,
        /// Whether the caller requested race-safe status inheritance.
        race_safe_status: bool,
        /// Owning actor inherited from the engine (`None` if actor-less).
        actor_id: Option<Uuid>,
    },
    /// `record_completed` — post-dispatch status + output.
    Completed {
        /// Row / dispatch id.
        id: Uuid,
        /// Status tag (`"completed"`, `"failed"`, `"timeout"`,
        /// `"cancelled"`).
        status: String,
        /// Output payload.
        output: JsonValue,
        /// Wall-clock duration in ms.
        duration_ms: i32,
        /// Optional error message (non-None on failures).
        error_message: Option<String>,
    },
    /// `resolve_module_id` — translation of a logical module id
    /// (e.g. template id) to the canonical id recorded on execution.
    ResolveModuleId {
        /// The id the caller asked about.
        input: Uuid,
        /// The id the store returned.
        output: Uuid,
    },
}

/// [`ModuleExecutionStore`] that records every call and lets the test
/// configure a template-id → wasm-module-id mapping.
#[derive(Clone, Default)]
pub struct CaptureModuleExecutionStore {
    calls: Arc<Mutex<Vec<ExecutionStoreCall>>>,
    /// Optional `template_id → wasm_modules.id` mapping returned by
    /// `resolve_module_id`. Unmapped ids pass through unchanged.
    resolver_map: Arc<Mutex<std::collections::HashMap<Uuid, Uuid>>>,
}

impl CaptureModuleExecutionStore {
    /// Build an empty capture store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the id returned by `resolve_module_id` when
    /// asked about `template_id`.
    pub fn with_wasm_module_id(self, template_id: Uuid, wasm_module_id: Uuid) -> Self {
        self.resolver_map
            .lock()
            .expect("CaptureModuleExecutionStore mutex poisoned")
            .insert(template_id, wasm_module_id);
        self
    }

    /// Snapshot of recorded calls.
    pub fn calls(&self) -> Vec<ExecutionStoreCall> {
        self.calls
            .lock()
            .expect("CaptureModuleExecutionStore mutex poisoned")
            .clone()
    }

    /// Count of recorded calls.
    pub fn len(&self) -> usize {
        self.calls
            .lock()
            .expect("CaptureModuleExecutionStore mutex poisoned")
            .len()
    }

    /// True when no calls have been recorded.
    pub fn is_empty(&self) -> bool {
        self.calls
            .lock()
            .expect("CaptureModuleExecutionStore mutex poisoned")
            .is_empty()
    }
}

impl std::fmt::Debug for CaptureModuleExecutionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureModuleExecutionStore")
            .field("len", &self.len())
            .finish()
    }
}

#[async_trait]
impl ModuleExecutionStore for CaptureModuleExecutionStore {
    async fn record_started(&self, ctx: ExecutionStartedContext<'_>) -> Result<(), BoxError> {
        self.calls
            .lock()
            .expect("CaptureModuleExecutionStore mutex poisoned")
            .push(ExecutionStoreCall::Started {
                id: ctx.id,
                module_id: ctx.module_id,
                user_id: ctx.user_id,
                workflow_execution_id: ctx.workflow_execution_id,
                input: ctx.input.clone(),
                trigger_type: ctx.trigger_type.to_string(),
                race_safe_status: ctx.race_safe_status,
                actor_id: ctx.actor_id,
            });
        Ok(())
    }

    async fn record_completed(
        &self,
        id: Uuid,
        status: &str,
        output: &JsonValue,
        duration_ms: i32,
        error_message: Option<&str>,
    ) -> Result<(), BoxError> {
        self.calls
            .lock()
            .expect("CaptureModuleExecutionStore mutex poisoned")
            .push(ExecutionStoreCall::Completed {
                id,
                status: status.to_string(),
                output: output.clone(),
                duration_ms,
                error_message: error_message.map(ToString::to_string),
            });
        Ok(())
    }

    async fn resolve_module_id(&self, id_or_template: Uuid) -> Uuid {
        let output = self
            .resolver_map
            .lock()
            .expect("CaptureModuleExecutionStore mutex poisoned")
            .get(&id_or_template)
            .copied()
            .unwrap_or(id_or_template);
        self.calls
            .lock()
            .expect("CaptureModuleExecutionStore mutex poisoned")
            .push(ExecutionStoreCall::ResolveModuleId {
                input: id_or_template,
                output,
            });
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn capture_event_sink_records_in_order() {
        let sink = CaptureEventSink::new();
        assert!(sink.is_empty());

        sink.emit(NodeEventWrite {
            execution_id: Uuid::nil(),
            event_type: "node_started".to_string(),
            node_id: Some(Uuid::nil()),
            status: "Running".to_string(),
            log_message: None,
            iteration_index: None,
            error_class: None,
        })
        .await;
        sink.emit(NodeEventWrite {
            execution_id: Uuid::nil(),
            event_type: "node_completed".to_string(),
            node_id: Some(Uuid::nil()),
            status: "Completed".to_string(),
            log_message: None,
            iteration_index: None,
            error_class: None,
        })
        .await;

        assert_eq!(sink.len(), 2);
        assert_eq!(sink.events()[0].event_type, "node_started");
        assert_eq!(sink.events()[1].event_type, "node_completed");
        assert_eq!(sink.events_of_type("node_completed").len(), 1);
    }

    #[tokio::test]
    async fn capture_module_execution_store_resolves_with_map() {
        let template = Uuid::new_v4();
        let wasm = Uuid::new_v4();
        let store = CaptureModuleExecutionStore::new().with_wasm_module_id(template, wasm);

        assert_eq!(store.resolve_module_id(template).await, wasm);
        // Unmapped ids pass through.
        let other = Uuid::new_v4();
        assert_eq!(store.resolve_module_id(other).await, other);
        assert_eq!(store.len(), 2);
    }
}
