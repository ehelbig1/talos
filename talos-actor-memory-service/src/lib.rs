//! # Actor Memory Service (controller-side glue)
//!
//! Thin re-export layer over [`talos_memory`]. The actual SQL, embedding,
//! and search logic lives in the shared `talos-memory` crate so the worker
//! can call the same code path when a WASM sandbox hits
//! `talos::core::agent_memory::*` (see `worker/src/host_impl.rs`).
//!
//! Controller-specific responsibilities kept here:
//!   - `GRAPH_SERVICE` — `OnceLock<graph_rag::GraphRagService>` used by
//!     many older call sites. Populated at controller startup.
//!   - `ControllerGraphHook` — adapter registered with
//!     `talos_memory::register_graph_hook` so every memory write across
//!     the workspace runs entity extraction through Neo4j.
//!
//! All constants, types, and functions from the original module are
//! re-exported so downstream code doesn't need to change its import
//! paths.

// Re-export everything the rest of the controller was using.
#[allow(unused_imports)]
pub use talos_memory::{
    backfill_embeddings, backfill_embeddings_for_actor, count_memories, default_expires_at, forget,
    forget_exact_in_tx, forget_keys_in_tx, forget_prefix, key_exists_at_all, list_memories,
    measure_and_forget_keys_in_tx, measure_value_bytes_in_tx, persist_memory, persist_memory_in_tx,
    persist_memory_with_metadata, recall_exact, recall_hyde, recall_keyword, recall_semantic,
    refresh_ttl, sweep_expired, validate_memory_type, ForgetOutcome, MemoryHit, MemoryMeta,
    MemoryRow, PersistOutcome, SearchMethod, SearchOutcome, MAX_LIST_LIMIT, MAX_MEMORIES_PER_ACTOR,
    MAX_VALUE_BYTES, MEMORY_TYPES,
};

/// Re-export the canonical graph-service singleton from `talos-graph-rag`.
/// Pre-r293 this OnceLock lived here; moving it to the crate that owns
/// `GraphRagService` broke the actor_memory_service ↔ workflow_repository
/// import cycle. Existing call sites (`actor_memory_service::GRAPH_SERVICE`)
/// keep working through this re-export.
pub use talos_graph_rag::GRAPH_SERVICE;

/// Adapter that hands graph extraction to `GRAPH_SERVICE` via the
/// crate-level hook. Registered once at controller startup (in
/// `main.rs`) immediately after `GRAPH_SERVICE.set(...)`.
struct ControllerGraphHook;

impl talos_memory::GraphHook for ControllerGraphHook {
    fn extract(
        &self,
        actor_id: uuid::Uuid,
        key: String,
        value: serde_json::Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>> {
        Box::pin(async move {
            if let Some(graph) = GRAPH_SERVICE.get() {
                graph
                    .extract_and_store_entities(actor_id, &key, &value)
                    .await?;
            }
            Ok(())
        })
    }
}

/// Called once at controller startup. Idempotent.
pub fn install_graph_hook() {
    talos_memory::register_graph_hook(std::sync::Arc::new(ControllerGraphHook));
}

/// Optionally inject the actor's most-relevant recent memories into a
/// workflow trigger input under the `__actor_context__` key. Used by
/// every dispatch path that runs an actor-bound workflow synchronously
/// or asynchronously (`trigger_workflow`, `test_workflow`,
/// `test_workflow_draft`, future replay paths).
///
/// No-op when `inject` is false, `actor_id` is None, the actor has no
/// relevant memories, or `input` is not a JSON object. The opt-in
/// default mirrors the security stance documented on
/// `handle_trigger_workflow`: actor memories may carry sensitive values
/// (PII, tokens, persona notes) and end up inline in execution traces
/// once injected, so the caller must pass `inject = true` deliberately.
///
/// `max_memories` is clamped at the call site (typically 50) — the
/// repo enforces nothing here. `context_hint` is forwarded to the
/// graph-RAG-backed `get_relevant_actor_context` so injection picks
/// the most pertinent memories rather than just the most recent.
pub async fn inject_actor_context_into_input(
    workflow_repo: &talos_workflow_repository::WorkflowRepository,
    input: &mut serde_json::Value,
    actor_id: Option<uuid::Uuid>,
    inject: bool,
    max_memories: usize,
    context_hint: Option<&str>,
) {
    if !inject {
        return;
    }
    let Some(actor_id) = actor_id else {
        return;
    };
    // MCP-453: pre-fix the DB error was swallowed by
    // `.unwrap_or_default()` — operators saw silent "no context
    // injected" rather than the real cause (Postgres down, permission
    // error, schema skew). Log at warn so the failure is observable
    // while preserving the best-effort contract that caller code
    // relies on.
    let memories = match workflow_repo
        .get_relevant_actor_context(actor_id, max_memories, context_hint)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(
                %actor_id,
                error = %e,
                "inject_actor_context_into_input: get_relevant_actor_context failed; \
                 proceeding without __actor_context__"
            );
            Vec::new()
        }
    };
    if memories.is_empty() {
        return;
    }
    let context = talos_memory::actor_context::assemble_payload(actor_id, &memories);
    if let Some(obj) = input.as_object_mut() {
        obj.insert("__actor_context__".to_string(), context);
    }
}
