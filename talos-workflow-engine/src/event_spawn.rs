//! Fire-and-forget helper for emitting execution events through a
//! `dyn EventSink`. `tokio::spawn`s the actual emit so the dispatch
//! loop never waits on the sink. No-op when `sink` is `None`.
//!
//! Lives in this crate (not `talos-workflow-engine-core`) because it depends
//! on the Tokio runtime. Consumers using a different executor can write
//! their own equivalent in ~5 lines.

use std::sync::Arc;

use talos_workflow_engine_core::{EventSink, NodeEventWrite};

/// Clone the sink `Arc` once and `tokio::spawn` the actual emit so the
/// dispatch loop never waits on the sink. If `sink` is `None` the call
/// is a no-op. Requires a Tokio runtime context to spawn in.
pub fn emit_event_spawn(sink: &Option<Arc<dyn EventSink>>, event: NodeEventWrite) {
    let Some(sink) = sink else {
        return;
    };
    let sink = Arc::clone(sink);
    tokio::spawn(async move {
        sink.emit(event).await;
    });
}
