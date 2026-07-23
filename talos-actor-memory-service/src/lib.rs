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
    persist_memory_with_metadata, persist_memory_with_metadata_typed, recall_exact, recall_hyde,
    recall_keyword, recall_semantic, refresh_ttl, sweep_expired, validate_memory_type,
    ForgetOutcome, MemoryHit, MemoryMeta, MemoryRow, MemoryWriteError, PersistOutcome,
    SearchMethod, SearchOutcome, MAX_LIST_LIMIT, MAX_MEMORIES_PER_ACTOR, MAX_VALUE_BYTES,
    MEMORY_TYPES,
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

/// Hard cap on memories re-processed by one `graph_backfill` call.
/// Extraction is one LLM call per memory (~5-10 s on a local 7B model),
/// so this bounds a single background run to a predictable worst-case
/// (~35 min at 200 × 10 s) rather than letting a caller queue an
/// actor's entire memory (`MAX_MEMORIES_PER_ACTOR` can be thousands).
/// Callers re-invoke for the next batch; the Neo4j MERGEs are
/// idempotent so overlap is harmless.
pub const MAX_BACKFILL_BATCH: i64 = 200;

/// Outcome of a `start_graph_backfill` request. Every variant is a
/// successful protocol response — the handler reports honestly rather
/// than erroring on "nothing to do".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackfillStart {
    /// A background task was spawned for `queued` live memories.
    /// Progress is observable via `graph_stats` (node/edge counts +
    /// `extraction_metrics`).
    Started { queued: usize },
    /// A backfill for this actor is already running — nothing spawned.
    /// One-at-a-time per actor keeps the LLM load bounded and the
    /// runs non-interleaved.
    AlreadyRunning,
    /// `GRAPH_SERVICE` isn't initialized (Neo4j not configured).
    GraphUnavailable,
}

/// Per-actor in-flight backfill registry. Bounded by construction: an
/// entry exists only while its background task runs (removed by
/// [`BackfillGuard::drop`], which runs even on task panic-unwind), so
/// this can't accumulate — no sweep needed (the keyed-DashMap sweep
/// rule applies to maps whose entries OUTLIVE their work).
static BACKFILLS_IN_FLIGHT: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashSet<uuid::Uuid>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

/// RAII removal from [`BACKFILLS_IN_FLIGHT`] — held by the background
/// task so completion, early-return, AND panic all release the slot.
struct BackfillGuard(uuid::Uuid);

impl Drop for BackfillGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = BACKFILLS_IN_FLIGHT.lock() {
            set.remove(&self.0);
        }
    }
}

/// Re-run graph-RAG entity extraction over an actor's LIVE memories.
///
/// Extraction normally fires only at write time (`spawn_graph_extraction`
/// inside `persist_memory`), which leaves two permanent gaps: memories
/// written before an extraction backend existed, and memories whose
/// extraction failed transiently (LLM outage) — both stay graph-less
/// forever. This backfill closes them.
///
/// Contract:
/// * **Tenancy is the CALLER's job** — the MCP handler gates on
///   `require_owned_actor` before invoking. This function trusts
///   `actor_id`.
/// * **Tier gate is NOT bypassed** — extraction goes through
///   `extract_and_store_entities`, which applies the same per-actor
///   `max_llm_tier` decision as the write path. A tier1 actor's
///   backfill queues rows but extracts none of them (each skip is
///   counted in `extraction_metrics.skipped_tier_gate`).
/// * **Bounded**: `limit` is clamped to `1..=MAX_BACKFILL_BATCH`; one
///   run per actor at a time; the task processes memories SEQUENTIALLY
///   (≤1 extra concurrent LLM call on top of the write path's
///   semaphore-capped extractions).
/// * **Idempotent**: Neo4j MERGE semantics — re-extracting an
///   already-graphed memory converges, never duplicates.
/// * **Best-effort**: per-memory failures are logged and counted, never
///   abort the batch.
pub async fn start_graph_backfill(
    pool: &sqlx::Pool<sqlx::Postgres>,
    actor_id: uuid::Uuid,
    limit: Option<i64>,
    memory_type: Option<String>,
) -> anyhow::Result<BackfillStart> {
    let Some(graph) = GRAPH_SERVICE.get() else {
        return Ok(BackfillStart::GraphUnavailable);
    };

    let limit = limit.unwrap_or(50).clamp(1, MAX_BACKFILL_BATCH);

    // Claim the per-actor slot BEFORE the DB read so two concurrent
    // requests can't both load rows and race to spawn.
    {
        let mut set = BACKFILLS_IN_FLIGHT
            .lock()
            .map_err(|_| anyhow::anyhow!("backfill registry poisoned"))?;
        if !set.insert(actor_id) {
            return Ok(BackfillStart::AlreadyRunning);
        }
    }
    let guard = BackfillGuard(actor_id);

    // Load the ciphertext rows inline (one bounded SELECT — fast) so the
    // response carries an exact queued count; the slow part (decrypt +
    // one LLM call per memory) runs in the background task.
    let rows = {
        let mut conn = pool.acquire().await?;
        talos_memory::list_memories_with_ciphertext_scoped(
            &mut conn,
            actor_id,
            memory_type.as_deref(),
            limit,
        )
        .await?
        // `guard` drops on `?`-return above, releasing the slot.
    };

    if rows.is_empty() {
        drop(guard);
        return Ok(BackfillStart::Started { queued: 0 });
    }

    let queued = rows.len();
    // `graph` is `&'static GraphRagService` (the OnceLock is a `static`),
    // so it moves into the task without cloning the service.
    tokio::spawn(async move {
        // Owns `guard` — the slot releases when this task ends, however
        // it ends.
        let _guard = guard;
        let (mut extracted, mut skipped, mut failed) = (0usize, 0usize, 0usize);
        for row in &rows {
            let value = match talos_memory::decrypt_memory_list_row(row).await {
                Ok(v) => v,
                Err(e) => {
                    failed += 1;
                    tracing::warn!(
                        target: "talos_graph_rag",
                        actor_id = %actor_id,
                        key = %row.key,
                        error = %e,
                        "graph backfill: memory decrypt failed — skipping row"
                    );
                    continue;
                }
            };
            match graph
                .extract_and_store_entities(actor_id, &row.key, &value)
                .await
            {
                Ok(0) => skipped += 1,
                Ok(_) => extracted += 1,
                Err(e) => {
                    failed += 1;
                    tracing::warn!(
                        target: "talos_graph_rag",
                        actor_id = %actor_id,
                        key = %row.key,
                        error = %e,
                        "graph backfill: extraction failed for memory — continuing"
                    );
                }
            }
        }
        tracing::info!(
            target: "talos_graph_rag",
            actor_id = %actor_id,
            queued,
            extracted,
            skipped,
            failed,
            "graph backfill complete"
        );
    });

    Ok(BackfillStart::Started { queued })
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
///
/// `execution_id` is the id of the execution this context is being packed
/// for (minted before injection on the trigger path). It is forwarded to
/// `get_relevant_actor_context` so the smart path can record memory-rank
/// PROVENANCE (which keys + their ranking-feature snapshot) keyed by
/// execution when `ENABLE_MEMORY_RANK_PROVENANCE` is on. `None` on paths
/// with no durable execution (draft/test previews) — provenance is skipped.
pub async fn inject_actor_context_into_input(
    workflow_repo: &talos_workflow_repository::WorkflowRepository,
    input: &mut serde_json::Value,
    actor_id: Option<uuid::Uuid>,
    inject: bool,
    max_memories: usize,
    context_hint: Option<&str>,
    execution_id: Option<uuid::Uuid>,
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
        .get_relevant_actor_context(actor_id, max_memories, context_hint, execution_id)
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

#[cfg(test)]
mod backfill_guard_tests {
    use super::{BackfillGuard, BACKFILLS_IN_FLIGHT};
    use uuid::Uuid;

    /// Helper mirroring `start_graph_backfill`'s claim: returns true if
    /// the slot was free (and is now claimed), false if already held.
    fn try_claim(actor_id: Uuid) -> bool {
        BACKFILLS_IN_FLIGHT.lock().unwrap().insert(actor_id)
    }

    #[test]
    fn guard_releases_slot_on_drop() {
        let actor = Uuid::new_v4();
        assert!(try_claim(actor), "first claim should succeed");
        assert!(!try_claim(actor), "second claim while held must fail");
        {
            let _guard = BackfillGuard(actor);
            // guard drops at end of this scope
        }
        assert!(
            try_claim(actor),
            "slot must be reclaimable after the guard drops"
        );
        // cleanup
        BACKFILLS_IN_FLIGHT.lock().unwrap().remove(&actor);
    }

    #[test]
    fn guard_drop_on_panic_unwind_releases_slot() {
        let actor = Uuid::new_v4();
        // Simulate the background task panicking while holding the guard —
        // Drop still runs during unwind, so the slot must free.
        let result = std::panic::catch_unwind(|| {
            let _guard = BackfillGuard(actor);
            BACKFILLS_IN_FLIGHT.lock().unwrap().insert(actor);
            panic!("simulated task panic");
        });
        assert!(result.is_err(), "the closure should have panicked");
        assert!(
            try_claim(actor),
            "slot must be free after a panicking task's guard unwinds"
        );
        BACKFILLS_IN_FLIGHT.lock().unwrap().remove(&actor);
    }

    #[test]
    fn distinct_actors_do_not_block_each_other() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert!(try_claim(a));
        assert!(try_claim(b), "a different actor's backfill is independent");
        BACKFILLS_IN_FLIGHT.lock().unwrap().remove(&a);
        BACKFILLS_IN_FLIGHT.lock().unwrap().remove(&b);
    }
}
