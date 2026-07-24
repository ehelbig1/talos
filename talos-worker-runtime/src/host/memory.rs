//! `agent-memory` and `graph-memory` host interfaces (signed NATS-RPC
//! to the controller's memory / graph services).

use super::*;

// ============================================================================
// Agent Memory
// ============================================================================

/// All actor-memory host functions dispatch to the controller over
/// NATS. Rationale:
///
/// - Defense in depth. Every other WASM-bearing surface in Talos
///   (secrets, workflow state, actors) is brokered through the
///   controller. Memory used to be the exception — it either held a
///   DB pool in the worker or fell back to an in-process HashMap.
///   Both options widen the blast radius of a sandbox escape.
///
/// - Single source of truth. Write path goes through
///   `talos_memory::persist_memory`, which computes embeddings and
///   runs graph-RAG entity extraction. Read path goes through
///   `talos_memory::recall_semantic`, which hits the same pgvector
///   cosine query as MCP's `actor_recall_semantic`. Results are
///   guaranteed consistent across callers.
///
/// - No DB pool or embedding provider credentials in the worker
///   container. The worker only needs NATS to reach the controller.
///
/// MCP-604 (2026-05-12): per-method capability gate. The WIT linkage
/// restricts `talos:core/agent-memory` to `database-node`, `agent-node`,
/// and `automation-node` at compile time (verified by grep `import
/// agent-memory` in wit/talos.wit). The runtime gate is defense-in-depth
/// against mis-tagged modules or future world-set changes — `actor_id`
/// is set on the context whenever the workflow has an actor binding,
/// regardless of capability_world, so `mem_rpc_prereqs_owned` alone
/// does not enforce the boundary. Same shape as MCP-602 (wit_object_storage)
/// and MCP-603 (wit_state).
fn require_agent_memory_capability(
    world: &crate::wit_inspector::CapabilityWorld,
) -> Result<(), wit_agent_memory::Error> {
    use crate::wit_inspector::CapabilityWorld;
    if matches!(
        world,
        CapabilityWorld::Database | CapabilityWorld::Agent | CapabilityWorld::Trusted
    ) {
        Ok(())
    } else {
        tracing::warn!(
            ?world,
            "WASM module attempted wit_agent_memory call but lacks Database/Agent/Trusted capability"
        );
        Err(wit_agent_memory::Error::NotAvailable)
    }
}

impl wit_agent_memory::Host for TalosContext {
    async fn get(&mut self, key: String) -> Result<String, wit_agent_memory::Error> {
        // MCP-714 (2026-05-13): audit-ledger parity. Pre-fix the `?`
        // operator on `require_agent_memory_capability` propagated Err
        // without an audit row — operator-blind to the WORM ledger.
        // Same fix shape as MCP-712 (wit_state) / MCP-713 (wit_secrets).
        // The actor-memory namespace can hold PII / business-critical
        // recall content, so capability-deny probes against memory
        // surfaces are an important signal class.
        if require_agent_memory_capability(&self.capability_world).is_err() {
            self.record_capability_denied("agent-memory-get", "capability-world", &key)
                .await;
            return Err(wit_agent_memory::Error::NotAvailable);
        }
        // Fail-fast key validation (parity with set/delete + the controller's
        // memory_rpc verify(); see set for rationale).
        if talos_memory::validate_memory_key(&key).is_err() {
            return Err(wit_agent_memory::Error::InvalidInput);
        }
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let (actor_id, nats) = match mem_rpc_prereqs_owned(self) {
            Some(p) => p,
            None => return Err(wit_agent_memory::Error::NotAvailable),
        };
        let result = match call_memory_op(
            actor_id,
            nats,
            talos_memory::memory_rpc::MemoryOp::Get { key },
        )
        .await
        {
            Ok(talos_memory::memory_rpc::MemoryOpResult::GetValue { value, .. }) => {
                // Round-trip fidelity: `set("k", "x")` must yield `get("k") == "x"`.
                // The RPC ships back a JSON-encoded value because the storage
                // layer preserves JSON structure server-side. Unwrap a JSON
                // string literal back to its inner bytes; for objects/arrays
                // return the serialized JSON (which is what the guest wrote).
                let unwrapped = match serde_json::from_str::<serde_json::Value>(&value) {
                    Ok(serde_json::Value::String(s)) => s,
                    _ => value,
                };
                Ok(unwrapped)
            }
            Ok(_) => Err(wit_agent_memory::Error::NotAvailable),
            Err(e) => Err(map_mem_err(e)),
        };
        if let Some(ref m) = __metrics {
            m.record_host_function_call("agent_memory::get", __start.elapsed().as_millis() as f64);
        }
        result
    }

    /// DX-19 (2026-07-14): value + durability metadata, with an absent key
    /// surfaced as `Ok(None)` rather than an error. Carries the EXACT same
    /// gate set as `get` (capability-world gate + audit-ledger row on deny,
    /// canonical key validation, per-call metrics, signed-RPC prereqs) —
    /// the batch-method sibling-defense lesson: every new method gets the
    /// full gates, copied not approximated. Reuses the same
    /// `MemoryOp::Get` request (signed bytes unchanged); the reply now
    /// carries the timestamps.
    async fn get_entry(
        &mut self,
        key: String,
    ) -> Result<Option<wit_agent_memory::MemoryEntryDetail>, wit_agent_memory::Error> {
        if require_agent_memory_capability(&self.capability_world).is_err() {
            self.record_capability_denied("agent-memory-get-entry", "capability-world", &key)
                .await;
            return Err(wit_agent_memory::Error::NotAvailable);
        }
        // Fail-fast key validation (parity with get/set/delete + the
        // controller's memory_rpc verify()).
        if talos_memory::validate_memory_key(&key).is_err() {
            return Err(wit_agent_memory::Error::InvalidInput);
        }
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let (actor_id, nats) = match mem_rpc_prereqs_owned(self) {
            Some(p) => p,
            None => return Err(wit_agent_memory::Error::NotAvailable),
        };
        let result = match call_memory_op(
            actor_id,
            nats,
            talos_memory::memory_rpc::MemoryOp::Get { key },
        )
        .await
        {
            Ok(talos_memory::memory_rpc::MemoryOpResult::GetValue {
                value,
                created_at_unix,
                expires_at_unix,
                memory_type,
            }) => {
                // Same value round-trip as `get`: unwrap a JSON string
                // literal back to its inner bytes; objects/arrays stay
                // serialized JSON.
                let unwrapped = match serde_json::from_str::<serde_json::Value>(&value) {
                    Ok(serde_json::Value::String(s)) => s,
                    _ => value,
                };
                Ok(Some(wit_agent_memory::MemoryEntryDetail {
                    value: unwrapped,
                    // A real row always carries created_at; the `unwrap_or(0)`
                    // only guards a reply from a pre-DX-19 controller that
                    // omits the field (worker/controller version skew).
                    created_at_unix: created_at_unix.unwrap_or(0),
                    expires_at_unix,
                    memory_type: memory_type.unwrap_or_default(),
                }))
            }
            // Absent key is NOT an error for get-entry — the whole point of
            // the addition. The controller replies KeyNotFound (byte-identical
            // to the legacy `get` miss); we translate it to Ok(None) here.
            Err(talos_memory::memory_rpc::MemoryRpcError::KeyNotFound) => Ok(None),
            Ok(_) => Err(wit_agent_memory::Error::NotAvailable),
            Err(e) => Err(map_mem_err(e)),
        };
        if let Some(ref m) = __metrics {
            m.record_host_function_call(
                "agent_memory::get_entry",
                __start.elapsed().as_millis() as f64,
            );
        }
        result
    }

    async fn set(&mut self, key: String, value: String) -> Result<(), wit_agent_memory::Error> {
        // MCP-714 (2026-05-13): audit-parity — see `get` above for full
        // rationale. set is the highest-stakes of the keyed methods
        // because a denied write attempt is a stronger signal of
        // capability mismatch than a denied read.
        if require_agent_memory_capability(&self.capability_world).is_err() {
            self.record_capability_denied("agent-memory-set", "capability-world", &key)
                .await;
            return Err(wit_agent_memory::Error::NotAvailable);
        }
        // Write-ceiling gate: a read-only actor may recall from memory but
        // never mutate it. Inert unless `TALOS_WRITE_CEILING_ENFORCED=1`.
        if self.write_ceiling_refuses("agent-memory-set", &key).await {
            return Err(wit_agent_memory::Error::NotAvailable);
        }
        // Fail-fast key validation via the canonical validator the controller's
        // memory_rpc verify() also runs (trim, non-empty, ≤500 chars, no control
        // chars/null). Parity with the per-key caps on wit_cache (MCP-754) and
        // wit_state: rejects an over-long/invalid key here instead of HMAC-signing
        // and shipping a doomed payload the controller would reject anyway.
        if talos_memory::validate_memory_key(&key).is_err() {
            return Err(wit_agent_memory::Error::InvalidInput);
        }
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        if value.len() > talos_memory::MAX_VALUE_BYTES {
            return Err(wit_agent_memory::Error::StorageFull);
        }
        let (actor_id, nats) = match mem_rpc_prereqs_owned(self) {
            Some(p) => p,
            None => return Err(wit_agent_memory::Error::NotAvailable),
        };
        let json_val: serde_json::Value =
            serde_json::from_str(&value).unwrap_or(serde_json::Value::String(value));
        let result = match call_memory_op(
            actor_id,
            nats,
            talos_memory::memory_rpc::MemoryOp::Set {
                key,
                value: json_val,
                // The `set` binding is documented (wit/talos.wit) as *persistent*
                // KV storage. Persist as durable `episodic` memory at the
                // long-lived TTL ceiling rather than `working` (1 h): state a
                // module writes via `set` MUST survive between scheduled runs.
                // Pre-2026-07 this hardcoded `working`/1h, so any accumulating
                // state (e.g. a weekly CRM) silently reset to empty every run.
                // `episodic` (not `scratchpad`) so the value stays visible to
                // actor-context injection and behaves identically to the
                // engine's `__memory_write__` episodic durable-write path.
                memory_type: "episodic".to_string(),
                ttl_hours: Some(talos_memory::SET_KV_TTL_HOURS),
                metadata: None,
            },
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(talos_memory::memory_rpc::MemoryRpcError::StorageFull) => {
                Err(wit_agent_memory::Error::StorageFull)
            }
            Err(e) => Err(map_mem_err(e)),
        };
        if let Some(ref m) = __metrics {
            m.record_host_function_call("agent_memory::set", __start.elapsed().as_millis() as f64);
        }
        result
    }

    async fn delete(&mut self, key: String) -> Result<(), wit_agent_memory::Error> {
        // MCP-714 (2026-05-13): audit-parity — see `get` above.
        if require_agent_memory_capability(&self.capability_world).is_err() {
            self.record_capability_denied("agent-memory-delete", "capability-world", &key)
                .await;
            return Err(wit_agent_memory::Error::NotAvailable);
        }
        // Write-ceiling gate: read-only actors cannot delete memory.
        if self
            .write_ceiling_refuses("agent-memory-delete", &key)
            .await
        {
            return Err(wit_agent_memory::Error::NotAvailable);
        }
        // Fail-fast key validation (parity with get/set + the controller's
        // memory_rpc verify(); see set for rationale).
        if talos_memory::validate_memory_key(&key).is_err() {
            return Err(wit_agent_memory::Error::InvalidInput);
        }
        let (actor_id, nats) = match mem_rpc_prereqs_owned(self) {
            Some(p) => p,
            None => return Err(wit_agent_memory::Error::NotAvailable),
        };
        match call_memory_op(
            actor_id,
            nats,
            talos_memory::memory_rpc::MemoryOp::Delete { key },
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(map_mem_err(e)),
        }
    }

    async fn list_keys(
        &mut self,
        prefix: Option<String>,
    ) -> Result<Vec<String>, wit_agent_memory::Error> {
        // MCP-714 (2026-05-13): audit-parity. list_keys is the
        // enumeration surface — key names themselves may carry
        // semantic information that operators consider out-of-scope
        // for a Minimal/Unknown-world module. Repeated capability-
        // denied probes here are the highest-signal pattern for
        // detecting reconnaissance against the actor namespace.
        if require_agent_memory_capability(&self.capability_world).is_err() {
            let probe = prefix.as_deref().unwrap_or("");
            self.record_capability_denied("agent-memory-list-keys", "capability-world", probe)
                .await;
            return Err(wit_agent_memory::Error::NotAvailable);
        }
        let (actor_id, nats) = match mem_rpc_prereqs_owned(self) {
            Some(p) => p,
            None => return Err(wit_agent_memory::Error::NotAvailable),
        };
        match call_memory_op(
            actor_id,
            nats,
            talos_memory::memory_rpc::MemoryOp::ListKeys { prefix },
        )
        .await
        {
            Ok(talos_memory::memory_rpc::MemoryOpResult::Keys { keys }) => Ok(keys),
            Ok(_) => Err(wit_agent_memory::Error::NotAvailable),
            Err(e) => Err(map_mem_err(e)),
        }
    }

    async fn store_with_embedding(
        &mut self,
        entry: wit_agent_memory::MemoryEntry,
    ) -> Result<(), wit_agent_memory::Error> {
        // MCP-714 (2026-05-13): audit-parity. store_with_embedding is
        // the semantic-memory write path — a capability-deny here
        // means a module tried to poison the embedding index with
        // entries it shouldn't be allowed to write.
        if require_agent_memory_capability(&self.capability_world).is_err() {
            self.record_capability_denied(
                "agent-memory-store-with-embedding",
                "capability-world",
                &entry.key,
            )
            .await;
            return Err(wit_agent_memory::Error::NotAvailable);
        }
        // Write-ceiling gate: read-only actors cannot write semantic memory.
        if self
            .write_ceiling_refuses("agent-memory-store-with-embedding", &entry.key)
            .await
        {
            return Err(wit_agent_memory::Error::NotAvailable);
        }
        let (actor_id, nats) = match mem_rpc_prereqs_owned(self) {
            Some(p) => p,
            None => return Err(wit_agent_memory::Error::NotAvailable),
        };
        // The guest provides `value` as a plain string. Preserve it literally —
        // `get` MUST return the same bytes back. Parse into a JSON value if it
        // looks like JSON (so the DB gets a typed payload and `jsonb_path_ops`
        // filters work) but otherwise store as a JSON string.
        let value_json = serde_json::from_str::<serde_json::Value>(&entry.value)
            .unwrap_or(serde_json::Value::String(entry.value));
        let metadata_json: Option<serde_json::Value> = entry
            .metadata
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok());
        match call_memory_op(
            actor_id,
            nats,
            talos_memory::memory_rpc::MemoryOp::Set {
                key: entry.key,
                value: value_json,
                memory_type: "semantic".to_string(),
                ttl_hours: None,
                metadata: metadata_json,
            },
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(talos_memory::memory_rpc::MemoryRpcError::StorageFull) => {
                Err(wit_agent_memory::Error::StorageFull)
            }
            Err(e) => Err(map_mem_err(e)),
        }
    }

    async fn search(
        &mut self,
        query: String,
        limit: u32,
    ) -> Result<Vec<wit_agent_memory::SearchResult>, wit_agent_memory::Error> {
        // Bare search is a zero-exclusion specialisation of the filtered
        // variant — keeps the two host paths semantically identical.
        self.search_filtered(
            query,
            wit_agent_memory::SearchOptions {
                limit,
                exclude_kinds: Vec::new(),
            },
        )
        .await
    }

    async fn search_filtered(
        &mut self,
        query: String,
        opts: wit_agent_memory::SearchOptions,
    ) -> Result<Vec<wit_agent_memory::SearchResult>, wit_agent_memory::Error> {
        // MCP-714 (2026-05-13): audit-parity. search_filtered is the
        // semantic-recall surface — query text may contain PII so we
        // hash before recording into the WORM ledger. Same hashing
        // convention as the secret-access path (line ~2440) which uses
        // SHA-256 of the key_path; operators reading the ledger
        // should not learn raw search-query strings.
        if require_agent_memory_capability(&self.capability_world).is_err() {
            let query_hash = format!("{:x}", Sha256::digest(query.as_bytes()));
            self.record_capability_denied("agent-memory-search", "capability-world", &query_hash)
                .await;
            return Err(wit_agent_memory::Error::NotAvailable);
        }
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let (actor_id, nats) = match mem_rpc_prereqs_owned(self) {
            Some(p) => p,
            None => return Ok(vec![]),
        };
        // Dedupe + strip empties so the signed canonical bytes are stable
        // regardless of caller-supplied input shape. A guest passing
        // `["meeting_prep", "meeting_prep", ""]` signs the same bytes as
        // one passing `["meeting_prep"]`.
        let mut exclude = opts
            .exclude_kinds
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        exclude.sort();
        exclude.dedup();
        // `min_score: 0.3` aligns with the MCP `actor_recall_semantic`
        // default — tuned for nomic-embed-text score distributions
        // (genuine matches score 0.2-0.5, so 0.3 balances recall + quality).
        // For stricter filtering callers can post-filter the returned
        // `score` field in the sandbox.
        let result = match call_memory_op(
            actor_id,
            nats,
            talos_memory::memory_rpc::MemoryOp::Search {
                query,
                limit: opts.limit.min(50),
                min_score: 0.3,
                exclude_kinds: exclude,
            },
        )
        .await
        {
            Ok(talos_memory::memory_rpc::MemoryOpResult::SearchHits { hits, .. }) => Ok(hits
                .into_iter()
                .map(|h| wit_agent_memory::SearchResult {
                    key: h.key,
                    value: h.value,
                    score: h.score,
                    // Per-row metadata (JSON string of the JSONB column).
                    // Sandboxes that use metadata.kind for self-reference-
                    // loop filtering previously had to reconstruct it from
                    // out-of-band sources; now it's available in-line.
                    metadata: h.metadata,
                })
                .collect()),
            Ok(_) => Ok(vec![]),
            Err(e) => {
                tracing::debug!(error = ?e, "agent_memory::search_filtered RPC error");
                Err(map_mem_err(e))
            }
        };
        if let Some(ref m) = __metrics {
            m.record_host_function_call(
                "agent_memory::search_filtered",
                __start.elapsed().as_millis() as f64,
            );
        }
        result
    }
}

/// Fire-and-forget NATS publish for state write-through. Invoked
/// from `state::set` and `state::delete`; errors and missing
/// prerequisites are silently swallowed because durability is
/// best-effort (the in-process HashMap remains the primary store).
pub(crate) fn spawn_state_write_through(
    nats: Option<std::sync::Arc<async_nats::Client>>,
    execution_id: Option<&str>,
    actor_id: Option<uuid::Uuid>,
    key: &str,
    value: Option<&str>,
) {
    use talos_memory::state_rpc::{StateWriteRequest, SUBJECT_STATE_WRITE};
    let (Some(nats), Some(exec_id_str), Some(actor_id)) = (nats, execution_id, actor_id) else {
        return;
    };
    let Ok(exec_id) = uuid::Uuid::parse_str(exec_id_str) else {
        return;
    };
    let key = key.to_string();
    let (value, is_delete) = match value {
        Some(v) => (v.to_string(), false),
        None => (String::new(), true),
    };
    tokio::spawn(async move {
        // MCP-734 (2026-05-13): sibling of MCP-733. The fire-and-forget
        // state-write path discarded ALL error signals (sign failure,
        // serialize failure, NATS publish failure). User-facing
        // contract is best-effort, but operator contract requires
        // visibility into systemic failures. Log at WARN with
        // execution_id + actor_id so SIEM / dashboards can alert on
        // sustained failures (NATS outage, HMAC key not initialised,
        // etc.).
        let Some(req) = StateWriteRequest::new_signed(exec_id, actor_id, key, value, is_delete)
        else {
            tracing::warn!(
                target: "talos_rpc",
                execution_id = %exec_id,
                actor_id = %actor_id,
                "state-write-through: HMAC key unavailable — drop (worker bootstrap incomplete or rotation in flight)"
            );
            return;
        };
        let payload = match serde_json::to_vec(&req) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    target: "talos_rpc",
                    execution_id = %exec_id,
                    actor_id = %actor_id,
                    error = %e,
                    "state-write-through: payload serialize failed — drop (should not happen for well-formed request)"
                );
                return;
            }
        };
        if let Err(e) = nats.publish(SUBJECT_STATE_WRITE, payload.into()).await {
            tracing::warn!(
                target: "talos_rpc",
                execution_id = %exec_id,
                actor_id = %actor_id,
                error = %e,
                "state-write-through: NATS publish failed — guest sees Ok but state was not persisted"
            );
        }
    });
}

/// Extract the values needed for an outgoing memory RPC by value, so
/// the returned tuple has no lifetime tying it to `TalosContext`.
/// Needed because the host-trait `async fn`s must return `Send`
/// futures and `TalosContext` itself is `!Sync`.
fn mem_rpc_prereqs_owned(
    ctx: &TalosContext,
) -> Option<(uuid::Uuid, std::sync::Arc<async_nats::Client>)> {
    Some((ctx.actor_id?, ctx.nats_client.as_ref().cloned()?))
}

/// Dispatch a signed memory-RPC request and wait for the reply. All
/// arguments are owned so the future is `Send`.
// Child span under the per-job `job-execution` span (worker otel bridge). Signed
// RPC to the controller's memory service. `skip_all` keeps the actor's memory
// payloads out of the span; only the pseudonymous actor_id is recorded.
#[::tracing::instrument(name = "memory.rpc", skip_all, fields(actor_id = %actor_id))]
async fn call_memory_op(
    actor_id: uuid::Uuid,
    nats: std::sync::Arc<async_nats::Client>,
    op: talos_memory::memory_rpc::MemoryOp,
) -> Result<talos_memory::memory_rpc::MemoryOpResult, talos_memory::memory_rpc::MemoryRpcError> {
    use talos_memory::memory_rpc::{
        MemoryRpcError, MemoryRpcReply, MemoryRpcRequest, REQUEST_TIMEOUT_MS, SUBJECT_MEMORY_OP,
    };
    let req = match MemoryRpcRequest::new_signed(actor_id, op) {
        Some(r) => r,
        None => return Err(MemoryRpcError::Unauthorized),
    };
    let payload = serde_json::to_vec(&req)
        .map_err(|e| MemoryRpcError::Internal(format!("serialize: {e}")))?;

    let fut = nats.request(SUBJECT_MEMORY_OP, payload.into());
    let reply_msg =
        match tokio::time::timeout(std::time::Duration::from_millis(REQUEST_TIMEOUT_MS), fut).await
        {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                return Err(MemoryRpcError::Internal(format!(
                    "nats request failed: {e}"
                )))
            }
            Err(_) => return Err(MemoryRpcError::Timeout),
        };
    let reply: MemoryRpcReply = serde_json::from_slice(&reply_msg.payload)
        .map_err(|e| MemoryRpcError::Internal(format!("reply decode: {e}")))?;
    reply.result
}

fn map_mem_err(e: talos_memory::memory_rpc::MemoryRpcError) -> wit_agent_memory::Error {
    use talos_memory::memory_rpc::MemoryRpcError;
    match e {
        MemoryRpcError::KeyNotFound => wit_agent_memory::Error::KeyNotFound,
        MemoryRpcError::InvalidInput(_) => wit_agent_memory::Error::InvalidInput,
        MemoryRpcError::StorageFull => wit_agent_memory::Error::StorageFull,
        _ => wit_agent_memory::Error::NotAvailable,
    }
}

// ============================================================================
// Graph Memory — NATS-RPC to the controller's graph service.
//
// The Neo4j driver lives controller-side; workers dispatch a
// `GraphSearchRequest` over NATS (subject `talos.graph.search`) and
// await a `GraphSearchReply` within `REQUEST_TIMEOUT_MS`. See
// `talos_memory::graph_rpc` for the wire protocol and
// `controller/src/main.rs` for the corresponding subscriber.
// ============================================================================

impl wit_graph_memory::Host for TalosContext {
    #[::tracing::instrument(name = "graph.search", skip_all, fields(max_depth = max_depth, limit = limit))]
    async fn graph_search(
        &mut self,
        query: String,
        max_depth: u32,
        limit: u32,
    ) -> Result<wit_graph_memory::GraphContext, wit_graph_memory::Error> {
        // MCP-608 (2026-05-12): per-method capability gate. WIT linkage
        // restricts `talos:core/graph-memory` to database-node, agent-node,
        // automation-node (verified by grep `import graph-memory` in
        // wit/talos.wit) → CapabilityWorld set {Database, Agent, Trusted}.
        // Pre-fix: gated only via `actor_id.is_some()` check below — the
        // same gap MCP-604 (wit_agent_memory) closed. A mis-tagged
        // minimal-world module with an actor binding could issue graph-RAG
        // queries against the actor's Neo4j graph.
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Database | CapabilityWorld::Agent | CapabilityWorld::Trusted
        ) {
            tracing::warn!(
                world = ?self.capability_world,
                "WASM module attempted wit_graph_memory::graph_search but lacks Database/Agent/Trusted capability"
            );
            return Err(wit_graph_memory::Error::NotAvailable);
        }
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __res: Result<wit_graph_memory::GraphContext, wit_graph_memory::Error> = async {
            use talos_memory::graph_rpc::{
                GraphRpcError, GraphSearchReply, GraphSearchRequest, MAX_DEPTH, MAX_LIMIT,
                REQUEST_TIMEOUT_MS, SUBJECT_GRAPH_SEARCH,
            };

            if query.trim().is_empty() {
                return Err(wit_graph_memory::Error::InvalidInput);
            }
            let Some(actor_id) = self.actor_id else {
                return Err(wit_graph_memory::Error::NotAvailable);
            };
            let Some(nats) = self.nats_client.as_ref().cloned() else {
                return Err(wit_graph_memory::Error::NotAvailable);
            };

            let req = match GraphSearchRequest::new_signed(
                actor_id,
                query,
                max_depth.min(MAX_DEPTH),
                limit.clamp(1, MAX_LIMIT),
            ) {
                Some(r) => r,
                None => {
                    // HMAC key unavailable — fail closed rather than
                    // sending an unsigned request.
                    return Err(wit_graph_memory::Error::NotAvailable);
                }
            };
            let payload = match serde_json::to_vec(&req) {
                Ok(p) => p,
                Err(_) => return Err(wit_graph_memory::Error::Internal),
            };

            let fut = nats.request(SUBJECT_GRAPH_SEARCH, payload.into());
            let reply_msg = match tokio::time::timeout(
                std::time::Duration::from_millis(REQUEST_TIMEOUT_MS),
                fut,
            )
            .await
            {
                Ok(Ok(m)) => m,
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "graph-search NATS request failed");
                    return Err(wit_graph_memory::Error::NotAvailable);
                }
                Err(_) => return Err(wit_graph_memory::Error::Timeout),
            };

            let reply: GraphSearchReply = match serde_json::from_slice(&reply_msg.payload) {
                Ok(r) => r,
                Err(_) => return Err(wit_graph_memory::Error::Internal),
            };

            match reply.result {
                Ok(resp) => Ok(wit_graph_memory::GraphContext {
                    entity_count: resp.entity_count,
                    entities: resp
                        .entities
                        .into_iter()
                        .map(|h| wit_graph_memory::GraphHit {
                            entity_type: h.entity_type,
                            label: h.label,
                            distance: h.distance,
                            properties: h.properties,
                        })
                        .collect(),
                    relationships: resp.relationships,
                }),
                Err(GraphRpcError::NotAvailable) => Err(wit_graph_memory::Error::NotAvailable),
                Err(GraphRpcError::InvalidInput(_)) => Err(wit_graph_memory::Error::InvalidInput),
                Err(GraphRpcError::Timeout) => Err(wit_graph_memory::Error::Timeout),
                Err(GraphRpcError::Internal(_)) => Err(wit_graph_memory::Error::Internal),
                Err(GraphRpcError::Unauthorized) => Err(wit_graph_memory::Error::NotAvailable),
            }
        }
        .await;
        if let Some(ref m) = __metrics {
            m.record_host_function_call(
                "graph_memory::graph_search",
                __start.elapsed().as_millis() as f64,
            );
        }
        __res
    }
}
