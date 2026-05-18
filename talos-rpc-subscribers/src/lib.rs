//! # RPC subscribers
//!
//! Controller-side NATS subscribers for the four talos-memory RPCs:
//! `talos.memory.op`, `talos.graph.search`, `talos.database.query`,
//! and `talos.state.write`. Each subscriber verifies the HMAC +
//! freshness on incoming requests, acquires a semaphore permit to
//! bound concurrency, executes via `talos_memory::*` against the
//! controller's Postgres/Neo4j, and replies. The single
//! `record_rpc_metric` helper emits structured completion events
//! under `target = "talos_rpc"` for ops dashboards.
//!
//! Lifted out of `main.rs` 2026-04-14 once the file exceeded 3500
//! lines. Zero behaviour change from the extraction — the public
//! `spawn_*_subscriber` functions are the entry points and signatures
//! are unchanged.

use talos_actor_memory_service as actor_memory_service;

// `ms_to_datetime` and `escape_like_pattern` live in
// `talos_integration_state` — they are utilities of that
// data-plane module, reusable from any subscriber or direct caller.

// ============================================================================
// talos-memory NATS-RPC subscribers
// ============================================================================
//
// Both subscribers:
//   - Verify every request's HMAC-SHA256 signature before touching state.
//   - Bound concurrency via a tokio semaphore so a fan-out storm cannot
//     saturate the DB pool / embedding provider / Neo4j driver.
//   - Catch panics in the handler so one bad request never kills the
//     subscriber loop.
//
// The key (`WORKER_SHARED_KEY`) is registered earlier in main(), so
// `verify()` returns false if the key is missing — requests are
// rejected with Unauthorized rather than silently succeeding.

/// Process-lifetime random suffix for the database-RPC CTE wrap
/// name. Avoids collisions with user-supplied SQL that defines its
/// own CTE. Regenerated only on controller restart — the database
/// subscriber doesn't need per-request uniqueness; it just needs the
/// name to be unpredictable from inside the WASM sandbox.
fn rpc_cte_name() -> &'static str {
    use std::sync::OnceLock;
    static NAME: OnceLock<String> = OnceLock::new();
    NAME.get_or_init(|| {
        let id = uuid::Uuid::new_v4().simple().to_string();
        format!("_rpc_data_{}", &id[..16])
    })
    .as_str()
}

/// Emit a structured completion event for an RPC subscriber. Fields
/// are tagged `target = "talos_rpc"` so ops can filter logs or
/// aggregate them into Prometheus/OTel pipelines without each
/// subscriber growing its own metrics code path.
///
/// `queue_ms` measures time from request receipt to semaphore
/// permit acquisition; `exec_ms` measures permit-to-reply. Splitting
/// these lets operators distinguish backpressure (queue rising) from
/// downstream slowdowns (exec rising). For handlers that never
/// acquire a permit (fast-path rejections like HMAC failure),
/// `queue_ms == total` and `exec_ms == 0`.
/// L-24: graceful-drain helper for subscriber loops.
///
/// Stops waiting once `in_flight` empties OR the deadline elapses,
/// whichever comes first. On deadline-elapsed the remaining tasks are
/// `abort_all()`d so a stuck request doesn't hang the controller's
/// pod-termination grace window.
///
/// Pre-extraction this drain logic only existed in `spawn_memory_rpc_subscriber`;
/// the other request/reply subscribers (graph, database,
/// integration_state) dropped in-flight tasks on shutdown. A worker
/// mid-query would see a NATS request timeout instead of a clean
/// "subscriber shut down" reply. This helper is now invoked by every
/// request/reply subscriber for a uniform shutdown experience.
async fn graceful_drain(
    mut in_flight: tokio::task::JoinSet<()>,
    deadline_secs: u64,
    subject: &'static str,
) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(deadline_secs);
    while !in_flight.is_empty() {
        tokio::select! {
            biased;
            _ = in_flight.join_next() => {}
            _ = tokio::time::sleep_until(deadline) => {
                tracing::warn!(
                    subject,
                    remaining = in_flight.len(),
                    deadline_secs,
                    "RPC drain deadline reached — aborting remaining tasks"
                );
                in_flight.abort_all();
                break;
            }
        }
    }
}

fn record_rpc_metric(
    subject: &'static str,
    actor_id: uuid::Uuid,
    outcome: &'static str, // "ok" | "not_found" | "unauthorized" | "invalid" | "internal" | "timeout" | …
    queue_ms: u64,
    exec_ms: u64,
) {
    // L-22: success outcomes are high-volume and routine; demote to
    // debug! so production INFO logs aren't dominated by `rpc completed`
    // baseline noise. Failure outcomes stay at warn!/info! so they
    // remain visible without a level filter — failures are the
    // operationally interesting class. Operators who want every-RPC
    // tracing for capacity planning enable debug! for the talos_rpc
    // target.
    if outcome == "ok" {
        tracing::debug!(
            target: "talos_rpc",
            subject,
            actor_id = %actor_id,
            outcome,
            queue_ms,
            exec_ms,
            duration_ms = queue_ms + exec_ms,
            "rpc completed"
        );
    } else {
        tracing::warn!(
            target: "talos_rpc",
            subject,
            actor_id = %actor_id,
            outcome,
            queue_ms,
            exec_ms,
            duration_ms = queue_ms + exec_ms,
            "rpc completed (non-ok outcome)"
        );
    }
}

pub fn spawn_graph_rpc_subscriber(
    nats: std::sync::Arc<async_nats::Client>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use futures::StreamExt;
    use std::sync::Arc;
    use talos_memory::graph_rpc::{
        GraphHit as RpcHit, GraphRpcError, GraphSearchReply, GraphSearchRequest,
        GraphSearchResponse, MAX_DEPTH, MAX_IN_FLIGHT, MAX_LIMIT, SUBJECT_GRAPH_SEARCH,
    };
    tokio::spawn(async move {
        let sem = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));
        tracing::info!(
            subject = SUBJECT_GRAPH_SEARCH,
            max_in_flight = MAX_IN_FLIGHT,
            "Graph-RPC subscriber active"
        );

        let mut shutdown = shutdown;
        let mut in_flight: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        // MCP-1126 (2026-05-16): supervisor loop re-binds subscription
        // on stream-end. Sibling sweep of MCP-1119/1120/1121/1122 to
        // the controller-side signed-RPC subscribers — graph_rpc is
        // the worker's only path to Neo4j graph-RAG, so if this
        // subscriber dies on `sub.next() → None` (NATS reconnect
        // window, server-side unsubscribe, transient async-nats
        // subscription handoff) every worker graph-search call times
        // out until the controller restarts. The `in_flight`
        // JoinSet AND `sem` live OUTSIDE the supervisor loop so
        // existing in-flight work survives a re-bind.
        let mut backoff_secs: u64 = 1;
        'supervisor: loop {
        let mut sub = match nats.subscribe(SUBJECT_GRAPH_SEARCH).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    subject = SUBJECT_GRAPH_SEARCH,
                    error = %e,
                    backoff_secs,
                    "Graph-RPC subscribe failed; retrying after backoff (worker graph-search calls time out in the meantime)"
                );
                // Respect shutdown signal DURING the backoff so a
                // controller stop doesn't have to wait the full
                // backoff window before draining.
                tokio::select! {
                    _ = shutdown.changed() => break 'supervisor,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)) => {}
                }
                backoff_secs = (backoff_secs * 2).min(60);
                continue 'supervisor;
            }
        };
        backoff_secs = 1;
        let mut shutdown_requested = false;
        loop {
            let msg = tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    tracing::info!("RPC subscriber shutting down");
                    shutdown_requested = true;
                    break;
                }
                Some(_) = in_flight.join_next(), if !in_flight.is_empty() => continue,
                maybe_msg = sub.next() => match maybe_msg {
                    Some(m) => m,
                    None => break,
                },
            };
            let nats_client = nats.clone();
            let sem = sem.clone();
            in_flight.spawn(async move {
                let start = std::time::Instant::now();
                let reply_to = match msg.reply.clone() {
                    Some(r) => r,
                    None => return,
                };

                let req: GraphSearchRequest = match serde_json::from_slice(&msg.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        let reply = GraphSearchReply {
                            result: Err(GraphRpcError::InvalidInput(format!(
                                "malformed request: {e}"
                            ))),
                        };
                        let _ = nats_client
                            .publish(
                                reply_to,
                                serde_json::to_vec(&reply).unwrap_or_default().into(),
                            )
                            .await;
                        record_rpc_metric(
                            SUBJECT_GRAPH_SEARCH,
                            uuid::Uuid::nil(),
                            "invalid",
                            start.elapsed().as_millis() as u64,
                            0,
                        );
                        return;
                    }
                };

                if !req.verify() {
                    tracing::warn!(
                        actor_id = %req.actor_id,
                        "graph-search RPC: HMAC or freshness verification failed"
                    );
                    let reply = GraphSearchReply {
                        result: Err(GraphRpcError::Unauthorized),
                    };
                    let _ = nats_client
                        .publish(
                            reply_to,
                            serde_json::to_vec(&reply).unwrap_or_default().into(),
                        )
                        .await;
                    record_rpc_metric(
                        SUBJECT_GRAPH_SEARCH,
                        req.actor_id,
                        "unauthorized",
                        start.elapsed().as_millis() as u64,
                        0,
                    );
                    return;
                }

                if !talos_memory::rpc_auth::check_and_record_nonce(
                    talos_memory::graph_rpc::SUBJECT_NAME,
                    req.actor_id,
                    &req.nonce,
                ) {
                    tracing::warn!(
                        actor_id = %req.actor_id,
                        "graph-search RPC: nonce replay rejected"
                    );
                    let reply = GraphSearchReply {
                        result: Err(GraphRpcError::Unauthorized),
                    };
                    let _ = nats_client
                        .publish(
                            reply_to,
                            serde_json::to_vec(&reply).unwrap_or_default().into(),
                        )
                        .await;
                    record_rpc_metric(
                        SUBJECT_GRAPH_SEARCH,
                        req.actor_id,
                        "replay",
                        start.elapsed().as_millis() as u64,
                        0,
                    );
                    return;
                }

                let depth = req.max_depth.min(MAX_DEPTH);
                let limit = req.limit.clamp(1, MAX_LIMIT);
                if req.query.trim().is_empty() {
                    let reply = GraphSearchReply {
                        result: Err(GraphRpcError::InvalidInput(
                            "query must be non-empty".to_string(),
                        )),
                    };
                    let _ = nats_client
                        .publish(
                            reply_to,
                            serde_json::to_vec(&reply).unwrap_or_default().into(),
                        )
                        .await;
                    return;
                }

                let service = match actor_memory_service::GRAPH_SERVICE.get() {
                    Some(s) => s,
                    None => {
                        let reply = GraphSearchReply {
                            result: Err(GraphRpcError::NotAvailable),
                        };
                        let _ = nats_client
                            .publish(
                                reply_to,
                                serde_json::to_vec(&reply).unwrap_or_default().into(),
                            )
                            .await;
                        return;
                    }
                };

                // Bound concurrent Neo4j queries. Dropping the permit on
                // either branch releases it.
                let _permit = sem.acquire_owned().await;
                let permit_at = std::time::Instant::now();

                let ctx_result = service
                    .get_graph_context(req.actor_id, &req.query, depth as usize, limit as usize)
                    .await;

                let reply = match ctx_result {
                    Ok(json) => {
                        let entity_count = json
                            .get("entity_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as u32;
                        let mut entities: Vec<RpcHit> = Vec::new();
                        let mut edges: Vec<serde_json::Value> = Vec::new();
                        if let Some(arr) = json.get("entities").and_then(|v| v.as_array()) {
                            for ent in arr {
                                let label = ent
                                    .get("name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or_default()
                                    .to_string();
                                let entity_type = ent
                                    .get("type")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Unknown")
                                    .to_string();
                                let rels = ent
                                    .get("relationships")
                                    .and_then(|v| v.as_array())
                                    .cloned()
                                    .unwrap_or_default();
                                for r in &rels {
                                    if let Some(target) = r.get("target").and_then(|v| v.as_str()) {
                                        let edge_type = r
                                            .get("type")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or_default();
                                        edges.push(serde_json::json!({
                                            "src": label,
                                            "dst": target,
                                            "type": edge_type,
                                        }));
                                    }
                                }
                                entities.push(RpcHit {
                                    entity_type,
                                    label,
                                    distance: 0,
                                    properties: serde_json::to_string(&rels)
                                        .unwrap_or_else(|_| "[]".to_string()),
                                });
                            }
                        }
                        GraphSearchReply {
                            result: Ok(GraphSearchResponse {
                                entity_count,
                                entities,
                                relationships: serde_json::json!({ "edges": edges }).to_string(),
                            }),
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            actor_id = %req.actor_id,
                            query = %req.query,
                            error = %e,
                            "graph-search RPC: service error"
                        );
                        GraphSearchReply {
                            result: Err(GraphRpcError::Internal(e.to_string())),
                        }
                    }
                };

                let outcome = match &reply.result {
                    Ok(_) => "ok",
                    Err(GraphRpcError::Unauthorized) => "unauthorized",
                    Err(GraphRpcError::InvalidInput(_)) => "invalid",
                    Err(GraphRpcError::NotAvailable) => "not_available",
                    Err(GraphRpcError::Timeout) => "timeout",
                    Err(GraphRpcError::Internal(_)) => "internal",
                };
                let _ = nats_client
                    .publish(
                        reply_to,
                        serde_json::to_vec(&reply).unwrap_or_default().into(),
                    )
                    .await;
                record_rpc_metric(
                    SUBJECT_GRAPH_SEARCH,
                    req.actor_id,
                    outcome,
                    permit_at.saturating_duration_since(start).as_millis() as u64,
                    permit_at.elapsed().as_millis() as u64,
                );
            });
        }
            // Inner loop exited.
            if shutdown_requested {
                break 'supervisor;
            }
            // Stream ended (NATS reconnect / server-side unsub /
            // async-nats subscription handoff); supervisor re-binds.
            tracing::warn!(
                target: "talos_rpc",
                event_kind = "graph_rpc_subscriber_rebinding",
                "Graph-RPC subscriber stream ended; supervisor re-binding"
            );
            tokio::select! {
                _ = shutdown.changed() => break 'supervisor,
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
            }
        } // end 'supervisor

        // L-24: shared graceful-drain helper.
        graceful_drain(in_flight, 10, SUBJECT_GRAPH_SEARCH).await;
    });
}

pub fn spawn_memory_rpc_subscriber(
    nats: std::sync::Arc<async_nats::Client>,
    pool: sqlx::PgPool,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use futures::StreamExt;
    use std::sync::Arc;
    use talos_memory::memory_rpc::{
        MemoryHit as RpcMemHit, MemoryOp, MemoryOpResult, MemoryRpcError, MemoryRpcReply,
        MemoryRpcRequest, MAX_IN_FLIGHT, MAX_RESULT_LIMIT, SUBJECT_MEMORY_OP,
    };
    tokio::spawn(async move {
        let sem = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));
        tracing::info!(
            subject = SUBJECT_MEMORY_OP,
            max_in_flight = MAX_IN_FLIGHT,
            "Memory-RPC subscriber active"
        );

        let mut shutdown = shutdown;
        let mut in_flight: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        // MCP-1127 (2026-05-16): supervisor loop re-binds subscription
        // on stream-end. Sibling sweep of MCP-1126 to the memory_rpc
        // primitive — the worker's only path to actor_memory
        // operations (Get/Set/Delete/ListKeys/Search). Per CLAUDE.md
        // "Anything that needs to read or write actor_memory MUST go
        // through talos_memory::* functions" → workers ALWAYS use
        // this RPC for memory operations. Pre-fix `None => break` on
        // stream-end (NATS reconnect window, server-side unsub,
        // async-nats subscription handoff) → every worker memory
        // operation timed out until controller restart. Same
        // shape as MCP-1126: in_flight + sem outside supervisor for
        // permit-leak-safe re-binds.
        let mut backoff_secs: u64 = 1;
        'supervisor: loop {
        let mut sub = match nats.subscribe(SUBJECT_MEMORY_OP).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    subject = SUBJECT_MEMORY_OP,
                    error = %e,
                    backoff_secs,
                    "Memory-RPC subscribe failed; retrying after backoff (worker agent_memory calls time out in the meantime)"
                );
                tokio::select! {
                    _ = shutdown.changed() => break 'supervisor,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)) => {}
                }
                backoff_secs = (backoff_secs * 2).min(60);
                continue 'supervisor;
            }
        };
        backoff_secs = 1;
        let mut shutdown_requested = false;
        loop {
            let msg = tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    tracing::info!("RPC subscriber shutting down");
                    shutdown_requested = true;
                    break;
                }
                Some(_) = in_flight.join_next(), if !in_flight.is_empty() => continue,
                maybe_msg = sub.next() => match maybe_msg {
                    Some(m) => m,
                    None => break,
                },
            };
            let nats_client = nats.clone();
            let sem = sem.clone();
            let pool = pool.clone();
            in_flight.spawn(async move {
                let start = std::time::Instant::now();
                let reply_to = match msg.reply.clone() {
                    Some(r) => r,
                    None => return,
                };

                let send_err = |err: MemoryRpcError| {
                    let nats_client = nats_client.clone();
                    let reply_to = reply_to.clone();
                    async move {
                        let reply = MemoryRpcReply { result: Err(err) };
                        let _ = nats_client
                            .publish(
                                reply_to,
                                serde_json::to_vec(&reply).unwrap_or_default().into(),
                            )
                            .await;
                    }
                };

                let req: MemoryRpcRequest = match serde_json::from_slice(&msg.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        send_err(MemoryRpcError::InvalidInput(format!(
                            "malformed request: {e}"
                        )))
                        .await;
                        record_rpc_metric(
                            SUBJECT_MEMORY_OP,
                            uuid::Uuid::nil(),
                            "invalid",
                            start.elapsed().as_millis() as u64,
                            0,
                        );
                        return;
                    }
                };

                if !req.verify() {
                    tracing::warn!(
                        actor_id = %req.actor_id,
                        "memory RPC: HMAC or freshness verification failed"
                    );
                    send_err(MemoryRpcError::Unauthorized).await;
                    record_rpc_metric(
                        SUBJECT_MEMORY_OP,
                        req.actor_id,
                        "unauthorized",
                        start.elapsed().as_millis() as u64,
                        0,
                    );
                    return;
                }

                if !talos_memory::rpc_auth::check_and_record_nonce(
                    talos_memory::memory_rpc::SUBJECT_NAME,
                    req.actor_id,
                    &req.nonce,
                ) {
                    tracing::warn!(
                        actor_id = %req.actor_id,
                        "memory RPC: nonce replay rejected"
                    );
                    send_err(MemoryRpcError::Unauthorized).await;
                    record_rpc_metric(
                        SUBJECT_MEMORY_OP,
                        req.actor_id,
                        "replay",
                        start.elapsed().as_millis() as u64,
                        0,
                    );
                    return;
                }

                let _permit = sem.acquire_owned().await;
                let permit_at = std::time::Instant::now();

                let op_result = execute_memory_op(&pool, req.actor_id, req.op).await;

                let outcome_tag: &'static str = match &op_result {
                    Ok(_) => "ok",
                    // Distinct from "ok" so dashboards can alert on a
                    // spike (replay lag, actor-id mismatch, cache wipe)
                    // without being confused by normal traffic.
                    Err(MemoryRpcError::KeyNotFound) => "not_found",
                    Err(MemoryRpcError::Unauthorized) => "unauthorized",
                    Err(MemoryRpcError::InvalidInput(_)) => "invalid",
                    Err(MemoryRpcError::Timeout) => "timeout",
                    Err(MemoryRpcError::StorageFull) => "storage_full",
                    _ => "internal",
                };
                let reply = match op_result {
                    Ok(r) => MemoryRpcReply { result: Ok(r) },
                    Err(e) => {
                        tracing::warn!(
                            actor_id = %req.actor_id,
                            error = ?e,
                            "memory RPC: op failed"
                        );
                        MemoryRpcReply { result: Err(e) }
                    }
                };
                let _ = nats_client
                    .publish(
                        reply_to,
                        serde_json::to_vec(&reply).unwrap_or_default().into(),
                    )
                    .await;
                record_rpc_metric(
                    SUBJECT_MEMORY_OP,
                    req.actor_id,
                    outcome_tag,
                    permit_at.saturating_duration_since(start).as_millis() as u64,
                    permit_at.elapsed().as_millis() as u64,
                );
            });
        }
            // Inner loop exited.
            if shutdown_requested {
                break 'supervisor;
            }
            // Stream ended (NATS reconnect / server-side unsub /
            // async-nats subscription handoff); supervisor re-binds.
            tracing::warn!(
                target: "talos_rpc",
                event_kind = "memory_rpc_subscriber_rebinding",
                "Memory-RPC subscriber stream ended; supervisor re-binding"
            );
            tokio::select! {
                _ = shutdown.changed() => break 'supervisor,
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
            }
        } // end 'supervisor

        async fn execute_memory_op(
            pool: &sqlx::PgPool,
            actor_id: uuid::Uuid,
            op: MemoryOp,
        ) -> Result<MemoryOpResult, MemoryRpcError> {
            match op {
                MemoryOp::Get { key } => {
                    // MCP-836 (2026-05-14): canonical key validator at
                    // the RPC trust boundary. Pre-fix `key.is_empty()`
                    // let `Get("   ")` through; after MCP-834/835
                    // trimmed every write path, the worker would
                    // self-MISS its own data because reads weren't
                    // trimmed (the MCP-388 trim-asymmetry class
                    // applied to the worker entry point).
                    let key = talos_memory::validate_memory_key(&key)
                        .map_err(|msg| MemoryRpcError::InvalidInput(msg.into()))?;
                    match talos_memory::recall_exact(pool, actor_id, key).await {
                        Ok(Some(row)) => Ok(MemoryOpResult::GetValue {
                            value: serde_json::to_string(&row.value)
                                .unwrap_or_else(|_| "null".into()),
                        }),
                        Ok(None) => Err(MemoryRpcError::KeyNotFound),
                        Err(e) => Err(MemoryRpcError::Internal(e.to_string())),
                    }
                }
                MemoryOp::Set {
                    key,
                    value,
                    memory_type,
                    ttl_hours,
                    metadata,
                } => {
                    // MCP-836 (2026-05-14): validate at RPC boundary
                    // BEFORE persist. Pre-fix there was no validation
                    // here at all — the service catches empty + length
                    // but accepts whitespace-only and control-char/`\0`
                    // keys. The post-fix error classifier below relied
                    // on substring matching on the word "key" which
                    // captured almost any error (over-broad InvalidInput
                    // mapping) — the explicit validate-then-persist
                    // shape produces typed `InvalidInput` for key
                    // issues, leaving the substring matcher to only
                    // distinguish memory_type and too-large.
                    let key = talos_memory::validate_memory_key(&key)
                        .map_err(|msg| MemoryRpcError::InvalidInput(msg.into()))?;
                    match talos_memory::persist_memory_with_metadata(
                        pool,
                        actor_id,
                        key,
                        &value,
                        metadata.as_ref(),
                        &memory_type,
                        ttl_hours,
                    )
                    .await
                    {
                        Ok(_) => Ok(MemoryOpResult::Ok),
                        Err(e) => {
                            let s = e.to_string();
                            if s.contains("too large") {
                                Err(MemoryRpcError::StorageFull)
                            } else if s.contains("invalid memory_type") {
                                Err(MemoryRpcError::InvalidInput(s))
                            } else {
                                Err(MemoryRpcError::Internal(s))
                            }
                        }
                    }
                }
                MemoryOp::Delete { key } => {
                    // Hard delete — WIT `delete` guarantees removal, not
                    // a tombstone. MCP's actor_forget (soft delete)
                    // takes a different path.
                    //
                    // MCP-836 (2026-05-14): same trim-parity reasoning
                    // as Get above — `Delete("  foo  ")` against a
                    // trim-canonicalized key store would silently
                    // no-op, indistinguishable from "key never existed."
                    let key = talos_memory::validate_memory_key(&key)
                        .map_err(|msg| MemoryRpcError::InvalidInput(msg.into()))?;
                    match talos_memory::forget_exact(pool, actor_id, key).await {
                        Ok(_) => Ok(MemoryOpResult::Ok),
                        Err(e) => Err(MemoryRpcError::Internal(e.to_string())),
                    }
                }
                MemoryOp::ListKeys { prefix } => {
                    // L-23: clamp via the same MAX_RESULT_LIMIT constant
                    // that bounds Search. Pre-fix, ListKeys silently
                    // inherited a 1000-row cap inside `talos_memory::list_keys`
                    // that disagreed with the 200-row Search cap — operators
                    // tuning result-size budgets had to remember the asymmetry.
                    match talos_memory::list_keys_with_limit(
                        pool,
                        actor_id,
                        prefix.as_deref(),
                        MAX_RESULT_LIMIT as i64,
                    )
                    .await
                    {
                        Ok(keys) => Ok(MemoryOpResult::Keys { keys }),
                        Err(e) => Err(MemoryRpcError::Internal(e.to_string())),
                    }
                }
                MemoryOp::Search {
                    query,
                    limit,
                    min_score,
                    exclude_kinds,
                } => {
                    if query.trim().is_empty() {
                        return Err(MemoryRpcError::InvalidInput("empty query".into()));
                    }
                    let limit = limit.clamp(1, MAX_RESULT_LIMIT) as i64;
                    // MCP-1005 (2026-05-15): cap exclude_kinds at the
                    // controller-side trust boundary. Pre-fix the only
                    // bounds were the NATS payload limit (~1 MB) and the
                    // worker's voluntary dedup. A malicious or buggy
                    // worker could pack ~70 000 short strings into
                    // exclude_kinds within the NATS payload cap; the
                    // resulting SQL `WHERE metadata->>'kind' != ALL($N::text[])`
                    // performs an O(M) array scan per row in
                    // `recall_semantic_filtered`, multiplying out to
                    // O(N rows × M kinds) per Search call. With N rows
                    // = thousands per actor and M = tens of thousands,
                    // a single Search call can lock up Postgres CPU
                    // long enough to starve other queries.
                    //
                    // Intended use is exclude-synthetic-source-kinds:
                    // typical caller passes 1-5 entries ("meeting_prep",
                    // "recall", "daily_brief", "execution"). A cap of 64
                    // entries × 64 chars/entry is comfortably above any
                    // realistic ceiling AND bounds the per-row scan
                    // cost. Same defense-in-depth shape as MCP-656
                    // (metadata size cap) and MCP-432 (memory key
                    // length cap). Sibling class to MCP-982 (unbounded
                    // pagination loops) — every guest-controlled
                    // collection at an RPC trust boundary needs an
                    // explicit cap.
                    // MCP-1026 (2026-05-15): same caps now live in
                    // `memory_rpc::verify()` as module-level consts so
                    // cross-process callers share one source of truth.
                    // The local check stays for explicit
                    // operator-readable error messages (verify() just
                    // returns false; this branch surfaces the offending
                    // field count back to the worker).
                    use talos_memory::memory_rpc::{
                        MAX_EXCLUDE_KINDS, MAX_EXCLUDE_KIND_LEN,
                    };
                    if exclude_kinds.len() > MAX_EXCLUDE_KINDS {
                        return Err(MemoryRpcError::InvalidInput(format!(
                            "exclude_kinds too large ({} entries, max {})",
                            exclude_kinds.len(),
                            MAX_EXCLUDE_KINDS
                        )));
                    }
                    if let Some(oversize) = exclude_kinds
                        .iter()
                        .find(|k| k.len() > MAX_EXCLUDE_KIND_LEN)
                    {
                        return Err(MemoryRpcError::InvalidInput(format!(
                            "exclude_kinds entry too long ({} chars, max {})",
                            oversize.len(),
                            MAX_EXCLUDE_KIND_LEN
                        )));
                    }
                    // exclude_kinds flows from the worker's `search_filtered`
                    // host call through the signed canonical bytes; recall_semantic_filtered
                    // excludes rows whose metadata.kind ∈ the list at the DB
                    // layer so synthetic outputs never re-enter an LLM's
                    // source list.
                    let outcome = talos_memory::recall_semantic_filtered(
                        pool,
                        actor_id,
                        &query,
                        limit,
                        min_score,
                        None,
                        talos_memory::SearchMethod::Direct,
                        &exclude_kinds,
                    )
                    .await
                    .map_err(|e| MemoryRpcError::Internal(e.to_string()))?;
                    let method = outcome.method.to_string();
                    let hits: Vec<RpcMemHit> = outcome
                        .hits
                        .into_iter()
                        .map(|h| RpcMemHit {
                            key: h.key,
                            value: serde_json::to_string(&h.value).unwrap_or_default(),
                            score: h.score as f32,
                            metadata: h
                                .metadata
                                .as_ref()
                                .map(|m| serde_json::to_string(m).unwrap_or_default()),
                        })
                        .collect();
                    Ok(MemoryOpResult::SearchHits { hits, method })
                }
            }
        }
        // L-24: shared graceful-drain helper.
        graceful_drain(in_flight, 10, SUBJECT_MEMORY_OP).await;
    });
}

pub fn spawn_database_rpc_subscriber(
    nats: std::sync::Arc<async_nats::Client>,
    pool: sqlx::PgPool,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use futures::StreamExt;
    use sqlx::Row;
    use std::sync::Arc;
    use talos_memory::database_rpc::{
        DatabaseResult, DatabaseRpcError, DatabaseRpcReply, DatabaseRpcRequest, MAX_IN_FLIGHT,
        MAX_RESULT_BYTES, MAX_RESULT_ROWS, QUERY_TIMEOUT_SECS, SUBJECT_DATABASE_QUERY,
    };
    tokio::spawn(async move {
        let sem = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));
        tracing::info!(
            subject = SUBJECT_DATABASE_QUERY,
            max_in_flight = MAX_IN_FLIGHT,
            "Database-RPC subscriber active"
        );

        let mut shutdown = shutdown;
        let mut in_flight: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        // MCP-1128 (2026-05-16): supervisor loop re-binds subscription
        // on stream-end. Sibling sweep of MCP-1126/1127 to the
        // database_rpc primitive. Per CLAUDE.md the worker is
        // credential-free; `wit_database::execute_query` is the only
        // path for sandbox SQL. Pre-fix `None => break` on stream-end
        // (NATS reconnect window, server-side unsub, async-nats
        // subscription handoff) → every worker SQL query timed out
        // until controller restart, taking down every workflow that
        // uses the database WIT host fn.
        let mut backoff_secs: u64 = 1;
        'supervisor: loop {
        let mut sub = match nats.subscribe(SUBJECT_DATABASE_QUERY).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    subject = SUBJECT_DATABASE_QUERY,
                    error = %e,
                    backoff_secs,
                    "Database-RPC subscribe failed; retrying after backoff (worker execute_query calls time out in the meantime)"
                );
                tokio::select! {
                    _ = shutdown.changed() => break 'supervisor,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)) => {}
                }
                backoff_secs = (backoff_secs * 2).min(60);
                continue 'supervisor;
            }
        };
        backoff_secs = 1;
        let mut shutdown_requested = false;
        loop {
            let msg = tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    tracing::info!("RPC subscriber shutting down");
                    shutdown_requested = true;
                    break;
                }
                Some(_) = in_flight.join_next(), if !in_flight.is_empty() => continue,
                maybe_msg = sub.next() => match maybe_msg {
                    Some(m) => m,
                    None => break,
                },
            };
            let nats_client = nats.clone();
            let sem = sem.clone();
            let pool = pool.clone();
            in_flight.spawn(async move {
                let start = std::time::Instant::now();
                let reply_to = match msg.reply.clone() {
                    Some(r) => r,
                    None => return,
                };

                let send = |result: Result<DatabaseResult, DatabaseRpcError>| {
                    let nats_client = nats_client.clone();
                    let reply_to = reply_to.clone();
                    async move {
                        let reply = DatabaseRpcReply { result };
                        let _ = nats_client
                            .publish(
                                reply_to,
                                serde_json::to_vec(&reply).unwrap_or_default().into(),
                            )
                            .await;
                    }
                };

                let req: DatabaseRpcRequest = match serde_json::from_slice(&msg.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        send(Err(DatabaseRpcError::InvalidQuery(format!(
                            "malformed request: {e}"
                        ))))
                        .await;
                        record_rpc_metric(
                            SUBJECT_DATABASE_QUERY,
                            uuid::Uuid::nil(),
                            "invalid",
                            start.elapsed().as_millis() as u64,
                            0,
                        );
                        return;
                    }
                };

                if !req.verify() {
                    tracing::warn!(
                        actor_id = %req.actor_id,
                        "database RPC: HMAC or freshness verification failed"
                    );
                    send(Err(DatabaseRpcError::Unauthorized)).await;
                    record_rpc_metric(
                        SUBJECT_DATABASE_QUERY,
                        req.actor_id,
                        "unauthorized",
                        start.elapsed().as_millis() as u64,
                        0,
                    );
                    return;
                }

                if !talos_memory::rpc_auth::check_and_record_nonce(
                    talos_memory::database_rpc::SUBJECT_NAME,
                    req.actor_id,
                    &req.nonce,
                ) {
                    tracing::warn!(
                        actor_id = %req.actor_id,
                        "database RPC: nonce replay rejected"
                    );
                    send(Err(DatabaseRpcError::Unauthorized)).await;
                    record_rpc_metric(
                        SUBJECT_DATABASE_QUERY,
                        req.actor_id,
                        "replay",
                        start.elapsed().as_millis() as u64,
                        0,
                    );
                    return;
                }

                // M-7: controller-side AST re-parse as defense-in-depth.
                //
                // Worker-side `sqlparser` is the active validator, but
                // the CTE wrap below string-interpolates `req.sql` —
                // if a future sqlparser↔Postgres parse divergence is
                // found, an attacker-controlled sandbox could craft
                // SQL that sqlparser accepts as one statement but
                // Postgres parses as multiple, escaping the wrap.
                //
                // We re-parse here with the same dialect + version the
                // worker uses, requiring exactly one statement and
                // rejecting anything sqlparser can't parse. Cost: ~50-200µs
                // per query, well below the network + DB time. Closes
                // the parser-divergence gap by requiring the SAME
                // parser to accept the SQL on BOTH ends.
                {
                    use sqlparser::dialect::PostgreSqlDialect;
                    use sqlparser::parser::Parser;
                    let stmts = match Parser::parse_sql(&PostgreSqlDialect {}, &req.sql) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!(
                                target: "talos_rpc",
                                event_kind = "database_rpc_reparse_failed",
                                actor_id = %req.actor_id,
                                error = %e,
                                "database RPC: controller-side sqlparser rejected query — \
                                 possible worker bypass attempt or parser-divergence gap"
                            );
                            send(Err(DatabaseRpcError::InvalidQuery(
                                "controller rejected SQL".to_string(),
                            )))
                            .await;
                            record_rpc_metric(
                                SUBJECT_DATABASE_QUERY,
                                req.actor_id,
                                "invalid",
                                start.elapsed().as_millis() as u64,
                                0,
                            );
                            return;
                        }
                    };
                    if stmts.len() != 1 {
                        tracing::warn!(
                            target: "talos_rpc",
                            event_kind = "database_rpc_multi_statement",
                            actor_id = %req.actor_id,
                            statement_count = stmts.len(),
                            "database RPC: rejecting multi-statement query"
                        );
                        send(Err(DatabaseRpcError::InvalidQuery(
                            "exactly one statement required".to_string(),
                        )))
                        .await;
                        record_rpc_metric(
                            SUBJECT_DATABASE_QUERY,
                            req.actor_id,
                            "invalid",
                            start.elapsed().as_millis() as u64,
                            0,
                        );
                        return;
                    }

                    // MCP-473: controller-side mirror of the worker's
                    // `always_blocked_label` deny-list (MCP-472). The
                    // worker is the primary defense, but if a future
                    // worker upgrade has a divergence bug OR a worker
                    // is compromised in a way that preserves signed
                    // RPC framing, the controller still refuses the
                    // high-risk statement types. ~10-50ns per query.
                    // Cost is dwarfed by the network + DB time.
                    //
                    // Variant list kept in lockstep with
                    // `worker::sql_validator::always_blocked_label`.
                    // Deliberate duplication: if the two ever diverge
                    // the divergence becomes a defense-in-depth gain,
                    // not loss — the union catches both sides' new
                    // additions until the lag is resolved.
                    // MCP-540: sync to worker::sql_validator::always_blocked_label
                    // verbatim. Pre-sync the controller had only the MCP-473
                    // baseline + 8 Show variants; the worker had grown the
                    // MCP-519 additions (LOAD / INSTALL / PRAGMA / LockTables /
                    // Comment / Declare / etc.) + CopyIntoSnowflake + three
                    // more Show variants without the controller catching up.
                    // The "deliberate duplication" comment below explicitly
                    // calls out that the union catches both sides' new
                    // additions — but only while operators are willing to
                    // resolve the lag. This commit closes the lag.
                    use sqlparser::ast::Statement as S;
                    let blocked_label: Option<&'static str> = match &stmts[0] {
                        S::Copy { .. } | S::CopyIntoSnowflake { .. } => Some("COPY"),
                        S::SetRole { .. } => Some("SET ROLE"),
                        S::SetVariable { .. } => Some("SET"),
                        S::SetTimeZone { .. } => Some("SET TIME ZONE"),
                        S::SetNamesDefault { .. } | S::SetNames { .. } => Some("SET NAMES"),
                        S::SetTransaction { .. } => Some("SET TRANSACTION"),
                        S::ShowVariable { .. }
                        | S::ShowStatus { .. }
                        | S::ShowVariables { .. }
                        | S::ShowCreate { .. }
                        | S::ShowColumns { .. }
                        | S::ShowTables { .. }
                        | S::ShowDatabases { .. }
                        | S::ShowSchemas { .. }
                        | S::ShowViews { .. }
                        | S::ShowCollation { .. }
                        | S::ShowFunctions { .. } => Some("SHOW"),
                        S::LISTEN { .. } => Some("LISTEN"),
                        S::NOTIFY { .. } => Some("NOTIFY"),
                        S::UNLISTEN { .. } => Some("UNLISTEN"),
                        S::Prepare { .. } => Some("PREPARE"),
                        S::Execute { .. } => Some("EXECUTE"),
                        S::Deallocate { .. } => Some("DEALLOCATE"),
                        S::StartTransaction { .. } => Some("START TRANSACTION"),
                        S::Commit { .. } => Some("COMMIT"),
                        S::Rollback { .. } => Some("ROLLBACK"),
                        S::Savepoint { .. } => Some("SAVEPOINT"),
                        S::ReleaseSavepoint { .. } => Some("RELEASE SAVEPOINT"),
                        S::Discard { .. } => Some("DISCARD"),
                        S::Use(_) => Some("USE"),
                        // MCP-540: MCP-519 additions — each one parses with
                        // PostgreSqlDialect (sqlparser shares the layer
                        // across dialects) and carries real escalation /
                        // sandbox-escape risk if it ever lands at the DB.
                        // See `worker::sql_validator::always_blocked_label`
                        // for per-statement rationale; the list is mirrored
                        // here as the controller-side last line of defense.
                        S::Load { .. } => Some("LOAD"),
                        S::Install { .. } => Some("INSTALL"),
                        S::Pragma { .. } => Some("PRAGMA"),
                        S::LockTables { .. } => Some("LOCK TABLES"),
                        S::UnlockTables => Some("UNLOCK TABLES"),
                        S::Kill { .. } => Some("KILL"),
                        S::Comment { .. } => Some("COMMENT"),
                        S::Declare { .. } => Some("DECLARE"),
                        S::Fetch { .. } => Some("FETCH"),
                        S::Close { .. } => Some("CLOSE"),
                        S::Flush { .. } => Some("FLUSH"),
                        S::OptimizeTable { .. } => Some("OPTIMIZE TABLE"),
                        S::Msck { .. } => Some("MSCK"),
                        S::Cache { .. } => Some("CACHE"),
                        S::UNCache { .. } => Some("UNCACHE"),
                        S::Directory { .. } => Some("DIRECTORY"),
                        S::Unload { .. } => Some("UNLOAD"),
                        S::LoadData { .. } => Some("LOAD DATA"),
                        S::Assert { .. } => Some("ASSERT"),
                        _ => None,
                    };
                    if let Some(label) = blocked_label {
                        tracing::warn!(
                            target: "talos_rpc",
                            event_kind = "database_rpc_always_blocked",
                            actor_id = %req.actor_id,
                            blocked_statement = label,
                            "database RPC: rejecting unconditionally-blocked statement type \
                             — possible worker bypass (worker should already have refused)"
                        );
                        send(Err(DatabaseRpcError::InvalidQuery(format!(
                            "{} statements are not permitted",
                            label
                        ))))
                        .await;
                        record_rpc_metric(
                            SUBJECT_DATABASE_QUERY,
                            req.actor_id,
                            "always_blocked",
                            start.elapsed().as_millis() as u64,
                            0,
                        );
                        return;
                    }
                }

                let _permit = sem.acquire_owned().await;
                let permit_at = std::time::Instant::now();

                let result = if req.is_fetch {
                    // Wrap with a CTE so that `UPDATE ... RETURNING`
                    // and `INSERT ... RETURNING` work alongside
                    // `SELECT`. Postgres does not allow bare DML as a
                    // subquery (SELECT * FROM (UPDATE ...) fails),
                    // but does allow it in a CTE. One extra row
                    // beyond the cap lets us detect overflow without
                    // materialising the whole result set.
                    //
                    // The CTE name is suffixed with a random-per-start
                    // token so a user SQL that itself defines `WITH
                    // _rpc_data AS (...)` cannot collide with our
                    // wrap. Process-lifetime random is sufficient —
                    // the request carries the user's actor_id so an
                    // attacker can't brute-force collisions across
                    // tenants, and the suffix is unpredictable from
                    // the WASM sandbox.
                    let wrapped = format!(
                        "WITH {cte} AS ({user_sql}) \
                         SELECT COALESCE(json_agg(t), '[]'::json) AS json_res \
                         FROM (SELECT * FROM {cte} LIMIT {lim}) t",
                        cte = rpc_cte_name(),
                        user_sql = req.sql,
                        lim = MAX_RESULT_ROWS + 1
                    );
                    let mut q = sqlx::query(&wrapped);
                    for p in &req.params {
                        q = q.bind(p);
                    }
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(QUERY_TIMEOUT_SECS),
                        q.fetch_one(&pool),
                    )
                    .await
                    {
                        Ok(Ok(row)) => {
                            let json_val: serde_json::Value = match row.try_get("json_res") {
                                Ok(v) => v,
                                Err(e) => {
                                    send(Err(DatabaseRpcError::QueryError(format!(
                                        "json_res decode: {e}"
                                    ))))
                                    .await;
                                    return;
                                }
                            };
                            if let Some(arr) = json_val.as_array() {
                                if arr.len() > MAX_RESULT_ROWS {
                                    send(Err(DatabaseRpcError::ResultTooLarge(format!(
                                        "query returned more than {} rows — add LIMIT/OFFSET",
                                        MAX_RESULT_ROWS
                                    ))))
                                    .await;
                                    return;
                                }
                            }
                            let rows_json = json_val.to_string();
                            if rows_json.len() > MAX_RESULT_BYTES {
                                send(Err(DatabaseRpcError::ResultTooLarge(format!(
                                    "result {} bytes exceeds {}-byte cap",
                                    rows_json.len(),
                                    MAX_RESULT_BYTES
                                ))))
                                .await;
                                return;
                            }
                            Ok(DatabaseResult {
                                rows_json,
                                rows_affected: 0,
                            })
                        }
                        Ok(Err(e)) => Err(DatabaseRpcError::QueryError(e.to_string())),
                        Err(_) => Err(DatabaseRpcError::Timeout),
                    }
                } else {
                    let mut q = sqlx::query(&req.sql);
                    for p in &req.params {
                        q = q.bind(p);
                    }
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(QUERY_TIMEOUT_SECS),
                        q.execute(&pool),
                    )
                    .await
                    {
                        Ok(Ok(r)) => Ok(DatabaseResult {
                            rows_json: "[]".to_string(),
                            rows_affected: r.rows_affected(),
                        }),
                        Ok(Err(e)) => Err(DatabaseRpcError::QueryError(e.to_string())),
                        Err(_) => Err(DatabaseRpcError::Timeout),
                    }
                };

                let outcome = match &result {
                    Ok(_) => "ok",
                    Err(DatabaseRpcError::Unauthorized) => "unauthorized",
                    Err(DatabaseRpcError::InvalidQuery(_)) => "invalid",
                    Err(DatabaseRpcError::ConnectionFailed(_)) => "connection_failed",
                    Err(DatabaseRpcError::ResultTooLarge(_)) => "too_large",
                    Err(DatabaseRpcError::Timeout) => "timeout",
                    Err(DatabaseRpcError::QueryError(_)) => "query_error",
                };
                send(result).await;
                record_rpc_metric(
                    SUBJECT_DATABASE_QUERY,
                    req.actor_id,
                    outcome,
                    permit_at.saturating_duration_since(start).as_millis() as u64,
                    permit_at.elapsed().as_millis() as u64,
                );
            });
        }
            // Inner loop exited.
            if shutdown_requested {
                break 'supervisor;
            }
            // Stream ended (NATS reconnect / server-side unsub /
            // async-nats subscription handoff); supervisor re-binds.
            tracing::warn!(
                target: "talos_rpc",
                event_kind = "database_rpc_subscriber_rebinding",
                "Database-RPC subscriber stream ended; supervisor re-binding"
            );
            tokio::select! {
                _ = shutdown.changed() => break 'supervisor,
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
            }
        } // end 'supervisor

        // L-24: shared graceful-drain helper.
        graceful_drain(in_flight, 10, SUBJECT_DATABASE_QUERY).await;
    });
}

pub fn spawn_state_write_subscriber(
    nats: std::sync::Arc<async_nats::Client>,
    pool: sqlx::PgPool,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use futures::StreamExt;
    use std::sync::Arc;
    use talos_memory::state_rpc::{StateWriteRequest, MAX_IN_FLIGHT, SUBJECT_STATE_WRITE};
    tokio::spawn(async move {
        let sem = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));
        tracing::info!(
            subject = SUBJECT_STATE_WRITE,
            max_in_flight = MAX_IN_FLIGHT,
            "State-write subscriber active"
        );

        // Fire-and-forget: no reply subject, no response. We still
        // verify the HMAC, rate-limit, and write to execution_state.
        let mut shutdown = shutdown;
        let mut in_flight: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        // MCP-1129 (2026-05-16): supervisor loop re-binds subscription
        // on stream-end. Sibling sweep of MCP-1126/1127/1128 to
        // state_rpc — the worker's path for execution_state
        // durability writes. Unlike the other RPCs this is fire-and-
        // forget (no reply inbox), so a dead subscriber would NOT
        // surface as a worker timeout — workers' state-writes simply
        // vanish into NATS with no record on the controller side.
        // execution_state is the durable record of which workflow
        // execution wrote which key/value; silent loss == data loss
        // visible only when an operator queries the table and finds
        // gaps. Supervisor re-bind closes that silent-data-loss
        // window on NATS reconnects / subscription handoff.
        let mut backoff_secs: u64 = 1;
        'supervisor: loop {
        let mut sub = match nats.subscribe(SUBJECT_STATE_WRITE).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    subject = SUBJECT_STATE_WRITE,
                    error = %e,
                    backoff_secs,
                    "State-write subscribe failed; retrying after backoff (execution_state durability disabled in the meantime)"
                );
                tokio::select! {
                    _ = shutdown.changed() => break 'supervisor,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)) => {}
                }
                backoff_secs = (backoff_secs * 2).min(60);
                continue 'supervisor;
            }
        };
        backoff_secs = 1;
        let mut shutdown_requested = false;
        loop {
            let msg = tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    tracing::info!("RPC subscriber shutting down");
                    shutdown_requested = true;
                    break;
                }
                Some(_) = in_flight.join_next(), if !in_flight.is_empty() => continue,
                maybe_msg = sub.next() => match maybe_msg {
                    Some(m) => m,
                    None => break,
                },
            };
            let sem = sem.clone();
            let pool = pool.clone();
            in_flight.spawn(async move {
                let start = std::time::Instant::now();
                let req: StateWriteRequest = match serde_json::from_slice(&msg.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!(error = %e, "state-write: malformed payload dropped");
                        record_rpc_metric(
                            SUBJECT_STATE_WRITE,
                            uuid::Uuid::nil(),
                            "invalid",
                            start.elapsed().as_millis() as u64,
                            0,
                        );
                        return;
                    }
                };
                if !req.verify() {
                    tracing::warn!(
                        actor_id = %req.actor_id,
                        execution_id = %req.execution_id,
                        "state-write: HMAC or freshness verification failed — request dropped"
                    );
                    record_rpc_metric(
                        SUBJECT_STATE_WRITE,
                        req.actor_id,
                        "unauthorized",
                        start.elapsed().as_millis() as u64,
                        0,
                    );
                    return;
                }

                if !talos_memory::rpc_auth::check_and_record_nonce(
                    talos_memory::state_rpc::SUBJECT_NAME,
                    req.actor_id,
                    &req.nonce,
                ) {
                    tracing::warn!(
                        actor_id = %req.actor_id,
                        execution_id = %req.execution_id,
                        "state-write: nonce replay rejected"
                    );
                    record_rpc_metric(
                        SUBJECT_STATE_WRITE,
                        req.actor_id,
                        "replay",
                        start.elapsed().as_millis() as u64,
                        0,
                    );
                    return;
                }

                let _permit = sem.acquire_owned().await;
                let permit_at = std::time::Instant::now();

                // MCP-1006 (2026-05-15): controller-side key/value caps
                // for defense in depth. Pre-fix the only size bounds
                // were the worker-side check in
                // `wit_state::Host::set` (key ≤ 1024 chars,
                // value ≤ 1 MiB) and the NATS payload cap (~1 MiB).
                // A compromised or buggy worker that bypasses its own
                // checks could ship a fire-and-forget state_set RPC
                // with arbitrarily-large key or near-1 MiB value
                // — both signed correctly, both accepted by this
                // handler, both persisted to `execution_state` until
                // Postgres row-size or TOAST limits intervene. Without
                // these caps, repeated large writes inflate the WAL,
                // pin CPU on the autovacuum daemon, and grow
                // `execution_state` storage with no bound from this
                // side. Same sibling-defense class as MCP-1005
                // (Memory Search exclude_kinds cap) — voluntary
                // worker-side bounds are necessary but not sufficient.
                // The integration_state_rpc subscriber already
                // enforces `value ≤ 64 KiB`; this fix brings
                // state_rpc into the same defense posture.
                //
                // Limits mirror the worker-side checks so legitimate
                // traffic is unaffected:
                //   key:    1-1024 chars (matches `wit_state::set`)
                //   value:  ≤ 1 MiB     (matches `wit_state::set`)
                // Violations log + drop without responding (this is a
                // fire-and-forget subject — no reply channel) so a
                // compromised worker doesn't get an oracle for size
                // probing.
                //
                // MCP-1024 (2026-05-15): caps now also live in
                // `state_rpc::verify()` (sibling pattern to
                // integration_state_rpc) so cross-process callers
                // share one well-formed definition. The subscriber
                // keeps the explicit check for metric tagging and
                // operator-readable log lines; verify() handles
                // the structural rejection at sign-validation time.
                // Imported constants instead of re-declared locals
                // so the two stay in lockstep.
                use talos_memory::state_rpc::{MAX_STATE_KEY_LEN, MAX_STATE_VALUE_BYTES};
                if req.key.is_empty() || req.key.len() > MAX_STATE_KEY_LEN {
                    tracing::warn!(
                        target: "talos_rpc",
                        actor_id = %req.actor_id,
                        execution_id = %req.execution_id,
                        key_len = req.key.len(),
                        "state-write: rejecting oversized/empty key (possible worker bypass)"
                    );
                    record_rpc_metric(
                        SUBJECT_STATE_WRITE,
                        req.actor_id,
                        "invalid",
                        permit_at.saturating_duration_since(start).as_millis() as u64,
                        permit_at.elapsed().as_millis() as u64,
                    );
                    return;
                }
                if !req.is_delete && req.value.len() > MAX_STATE_VALUE_BYTES {
                    tracing::warn!(
                        target: "talos_rpc",
                        actor_id = %req.actor_id,
                        execution_id = %req.execution_id,
                        value_bytes = req.value.len(),
                        "state-write: rejecting oversized value (possible worker bypass)"
                    );
                    record_rpc_metric(
                        SUBJECT_STATE_WRITE,
                        req.actor_id,
                        "too_large",
                        permit_at.saturating_duration_since(start).as_millis() as u64,
                        permit_at.elapsed().as_millis() as u64,
                    );
                    return;
                }

                // MCP-733 (2026-05-13): log SQL errors on the state-write
                // path. Pre-fix the Err arms discarded the error entirely
                // (`Err(_) => "query_error"`) — under a DB outage, every
                // guest's `state_set` / `state_delete` silently lost
                // persistence with zero operational signal. Guests treat
                // state-write as fire-and-forget, so the user-facing
                // contract permits silent loss, but the OPERATOR contract
                // requires that errors be visible. Log at WARN so SIEM /
                // dashboard alerting can fire on sustained query_error
                // outcomes. Same operational-class fix as the canonical
                // "fire-and-forget swallows errors" anti-pattern from
                // `memory/patterns.md`.
                let outcome: &'static str = if req.is_delete {
                    match sqlx::query(
                        "DELETE FROM execution_state WHERE execution_id = $1 AND key = $2",
                    )
                    .bind(req.execution_id)
                    .bind(&req.key)
                    .execute(&pool)
                    .await
                    {
                        Ok(_) => "ok",
                        Err(e) => {
                            tracing::warn!(
                                target: "talos_rpc",
                                actor_id = %req.actor_id,
                                execution_id = %req.execution_id,
                                error = %e,
                                "state-write DELETE failed — guest sees no error (fire-and-forget)"
                            );
                            "query_error"
                        }
                    }
                } else {
                    match sqlx::query(
                        "INSERT INTO execution_state (execution_id, key, value, version, updated_at) \
                         VALUES ($1, $2, $3, 1, NOW()) \
                         ON CONFLICT (execution_id, key) DO UPDATE SET \
                           value = EXCLUDED.value, \
                           version = execution_state.version + 1, \
                           updated_at = NOW()",
                    )
                    .bind(req.execution_id)
                    .bind(&req.key)
                    .bind(&req.value)
                    .execute(&pool)
                    .await
                    {
                        Ok(_) => "ok",
                        Err(e) => {
                            tracing::warn!(
                                target: "talos_rpc",
                                actor_id = %req.actor_id,
                                execution_id = %req.execution_id,
                                error = %e,
                                "state-write UPSERT failed — guest sees no error (fire-and-forget)"
                            );
                            "query_error"
                        }
                    }
                };
                record_rpc_metric(
                    SUBJECT_STATE_WRITE,
                    req.actor_id,
                    outcome,
                    permit_at.saturating_duration_since(start).as_millis() as u64,
                    permit_at.elapsed().as_millis() as u64,
                );
            });
        }
            // Inner loop exited.
            if shutdown_requested {
                break 'supervisor;
            }
            // Stream ended (NATS reconnect / server-side unsub /
            // async-nats subscription handoff); supervisor re-binds.
            tracing::warn!(
                target: "talos_rpc",
                event_kind = "state_rpc_subscriber_rebinding",
                "State-write subscriber stream ended; supervisor re-binding"
            );
            tokio::select! {
                _ = shutdown.changed() => break 'supervisor,
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
            }
        } // end 'supervisor

        // L-24: shared graceful-drain helper.
        graceful_drain(in_flight, 10, SUBJECT_STATE_WRITE).await;
    });
}

// ============================================================================
// Integration state RPC subscriber
// ============================================================================
//
// Request/reply on `talos.integration_state.op` — the generic primitive
// that lets integrations (gcal, gmail, jira, ...) persist their own
// scoped state without per-integration tables. Rows are scoped by
// (integration_name, user_id, key); the subscriber enforces BOTH at
// every operation. HMAC signing + nonce replay cache prevent
// cross-integration and cross-user replays.
//
// Caps enforced here (not in SQL):
//   - value ≤ 64 KiB
//   - total rows per (integration_name, user_id) ≤ 10_000
// Duplicated against the client-side sign-time checks so a rogue client
// that bypasses signing still hits the ceiling.

pub fn spawn_integration_state_subscriber(
    nats: std::sync::Arc<async_nats::Client>,
    pool: sqlx::PgPool,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use futures::StreamExt;
    use std::sync::Arc;
    use talos_memory::integration_state_rpc::{
        IntegrationStateError, IntegrationStateReply, IntegrationStateRequest, MAX_IN_FLIGHT,
        SUBJECT_INTEGRATION_STATE_OP,
    };
    tokio::spawn(async move {
        let sem = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));
        tracing::info!(
            subject = SUBJECT_INTEGRATION_STATE_OP,
            max_in_flight = MAX_IN_FLIGHT,
            "Integration-state subscriber active"
        );

        let mut shutdown = shutdown;
        let mut in_flight: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        // MCP-1130 (2026-05-16): supervisor loop re-binds subscription
        // on stream-end. Completes the MCP-1126–1129 sweep across all
        // 5 signed-RPC subscribers. integration_state_rpc is the
        // generic primitive integrations use to persist their own
        // scoped state (gcal sync token, gmail watch history-id,
        // jira filter cursor, etc.) — a dead subscriber means
        // workers' integration-state writes time out → integrations
        // can't persist their sync progress → next poll re-fetches
        // from the beginning of history (gcal/gmail) or fails
        // outright (jira filter cursor lost). Re-bind closes that
        // gap on NATS reconnects / subscription handoff.
        let mut backoff_secs: u64 = 1;
        'supervisor: loop {
        let mut sub = match nats.subscribe(SUBJECT_INTEGRATION_STATE_OP).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    subject = SUBJECT_INTEGRATION_STATE_OP,
                    error = %e,
                    backoff_secs,
                    "Integration-state subscribe failed; retrying after backoff (worker integration_state calls time out in the meantime)"
                );
                tokio::select! {
                    _ = shutdown.changed() => break 'supervisor,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)) => {}
                }
                backoff_secs = (backoff_secs * 2).min(60);
                continue 'supervisor;
            }
        };
        backoff_secs = 1;
        let mut shutdown_requested = false;
        loop {
            let msg = tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    tracing::info!("RPC subscriber shutting down");
                    shutdown_requested = true;
                    break;
                }
                Some(_) = in_flight.join_next(), if !in_flight.is_empty() => continue,
                maybe_msg = sub.next() => match maybe_msg {
                    Some(m) => m,
                    None => break,
                },
            };
            let nats_client = nats.clone();
            let sem = sem.clone();
            let pool = pool.clone();
            in_flight.spawn(async move {
                let start = std::time::Instant::now();
                let reply_to = match msg.reply.clone() {
                    Some(r) => r,
                    None => return,
                };

                let send_err = |err: IntegrationStateError| {
                    let nats_client = nats_client.clone();
                    let reply_to = reply_to.clone();
                    async move {
                        let reply = IntegrationStateReply { result: Err(err) };
                        let _ = nats_client
                            .publish(
                                reply_to,
                                serde_json::to_vec(&reply).unwrap_or_default().into(),
                            )
                            .await;
                    }
                };

                let req: IntegrationStateRequest = match serde_json::from_slice(&msg.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        send_err(IntegrationStateError::InvalidInput(format!(
                            "malformed request: {e}"
                        )))
                        .await;
                        record_rpc_metric(
                            SUBJECT_INTEGRATION_STATE_OP,
                            uuid::Uuid::nil(),
                            "invalid",
                            start.elapsed().as_millis() as u64,
                            0,
                        );
                        return;
                    }
                };

                if !req.verify() {
                    tracing::warn!(
                        actor_id = %req.actor_id,
                        integration = %req.integration_name,
                        "integration-state RPC: HMAC or freshness verification failed"
                    );
                    send_err(IntegrationStateError::Unauthorized).await;
                    record_rpc_metric(
                        SUBJECT_INTEGRATION_STATE_OP,
                        req.actor_id,
                        "unauthorized",
                        start.elapsed().as_millis() as u64,
                        0,
                    );
                    return;
                }

                if !talos_memory::rpc_auth::check_and_record_nonce(
                    talos_memory::integration_state_rpc::SUBJECT_NAME,
                    req.actor_id,
                    &req.nonce,
                ) {
                    tracing::warn!(
                        actor_id = %req.actor_id,
                        integration = %req.integration_name,
                        "integration-state RPC: nonce replay rejected"
                    );
                    send_err(IntegrationStateError::Unauthorized).await;
                    record_rpc_metric(
                        SUBJECT_INTEGRATION_STATE_OP,
                        req.actor_id,
                        "replay",
                        start.elapsed().as_millis() as u64,
                        0,
                    );
                    return;
                }

                let _permit = sem.acquire_owned().await;
                let permit_at = std::time::Instant::now();

                let op_result = talos_integration_state::execute_op(
                    &pool,
                    &req.integration_name,
                    req.user_id,
                    req.op,
                )
                .await;

                let outcome_tag: &'static str = match &op_result {
                    Ok(_) => "ok",
                    Err(IntegrationStateError::KeyNotFound) => "not_found",
                    Err(IntegrationStateError::Unauthorized) => "unauthorized",
                    Err(IntegrationStateError::InvalidInput(_)) => "invalid",
                    Err(IntegrationStateError::Timeout) => "timeout",
                    Err(IntegrationStateError::StorageFull) => "storage_full",
                    _ => "internal",
                };
                let reply = match op_result {
                    Ok(r) => IntegrationStateReply { result: Ok(r) },
                    Err(e) => {
                        tracing::warn!(
                            actor_id = %req.actor_id,
                            integration = %req.integration_name,
                            error = ?e,
                            "integration-state RPC: op failed"
                        );
                        IntegrationStateReply { result: Err(e) }
                    }
                };
                let _ = nats_client
                    .publish(
                        reply_to,
                        serde_json::to_vec(&reply).unwrap_or_default().into(),
                    )
                    .await;
                record_rpc_metric(
                    SUBJECT_INTEGRATION_STATE_OP,
                    req.actor_id,
                    outcome_tag,
                    permit_at.saturating_duration_since(start).as_millis() as u64,
                    permit_at.elapsed().as_millis() as u64,
                );
            });
        }
            // Inner loop exited.
            if shutdown_requested {
                break 'supervisor;
            }
            // Stream ended (NATS reconnect / server-side unsub /
            // async-nats subscription handoff); supervisor re-binds.
            tracing::warn!(
                target: "talos_rpc",
                event_kind = "integration_state_rpc_subscriber_rebinding",
                "Integration-state subscriber stream ended; supervisor re-binding"
            );
            tokio::select! {
                _ = shutdown.changed() => break 'supervisor,
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
            }
        } // end 'supervisor

        // L-24: shared graceful-drain helper.
        graceful_drain(in_flight, 10, SUBJECT_INTEGRATION_STATE_OP).await;
    });
}

/// Background cleanup: evict expired integration_state rows every 5 min.
/// Matches actor_memory's sweep cadence + shutdown handling.
pub fn spawn_integration_state_sweeper(
    pool: sqlx::PgPool,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    const SWEEP_INTERVAL_SECS: u64 = 300;
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(SWEEP_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                _ = interval.tick() => {
                    // Bounded per-tick sweep. An unbounded DELETE could
                    // touch arbitrarily many rows in one transaction and
                    // hold row-locks long enough to stall writers. The
                    // subquery-with-LIMIT caps each tick; at the 5-min
                    // cadence a backlog catches up within a few iterations.
                    // 10k is a reasonable ceiling at personal scale; bump
                    // if operations ever see the deleted-count consistently
                    // equal to the batch size.
                    const SWEEP_BATCH_SIZE: i64 = 10_000;
                    match sqlx::query(
                        "DELETE FROM integration_state \
                         WHERE id IN ( \
                           SELECT id FROM integration_state \
                           WHERE expires_at IS NOT NULL AND expires_at < now() \
                           LIMIT $1 \
                         )",
                    )
                    .bind(SWEEP_BATCH_SIZE)
                    .execute(&pool)
                    .await
                    {
                        Ok(r) if r.rows_affected() > 0 => tracing::info!(
                            target: "talos_rpc",
                            subject = "talos.integration_state.sweep",
                            rows_deleted = r.rows_affected(),
                            batch_size = SWEEP_BATCH_SIZE,
                            "expired integration_state rows swept"
                        ),
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "integration_state sweep failed"),
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod helper_tests {
    use talos_integration_state::{escape_like_pattern, ms_to_datetime};

    #[test]
    fn ms_to_datetime_typical_epoch() {
        // 2023-01-01T00:00:00Z
        let ms = 1_672_531_200_000i64;
        let dt = ms_to_datetime(ms).expect("typical epoch must decode");
        assert_eq!(dt.timestamp_millis(), ms);
    }

    #[test]
    fn ms_to_datetime_rejects_i64_max() {
        // i64::MAX ms is ~292M years after epoch — far beyond chrono's
        // year-9999 ceiling. The RPC validator rejects these upstream,
        // but the subscriber must also fail closed if one slips through.
        assert!(ms_to_datetime(i64::MAX).is_none());
    }

    #[test]
    fn ms_to_datetime_rejects_i64_min() {
        assert!(ms_to_datetime(i64::MIN).is_none());
    }

    #[test]
    fn ms_to_datetime_accepts_zero() {
        // Epoch itself must decode — a Unix-epoch write is legitimate.
        let dt = ms_to_datetime(0).expect("epoch must decode");
        assert_eq!(dt.timestamp_millis(), 0);
    }

    #[test]
    fn escape_like_pattern_passthrough_literal() {
        assert_eq!(escape_like_pattern("watch_channel"), "watch\\_channel");
        assert_eq!(escape_like_pattern("foo"), "foo");
        assert_eq!(escape_like_pattern(""), "");
    }

    #[test]
    fn escape_like_pattern_escapes_all_metachars() {
        // `%` and `_` are LIKE wildcards; `\` is the escape char. All
        // three must be escaped — otherwise a caller passing `a%` gets
        // "anything starting with a" instead of literal `a%`.
        assert_eq!(escape_like_pattern("50%"), "50\\%");
        assert_eq!(escape_like_pattern("a_b"), "a\\_b");
        assert_eq!(escape_like_pattern("c\\d"), "c\\\\d");
        assert_eq!(escape_like_pattern("100%_done\\!"), "100\\%\\_done\\\\!");
    }

    #[test]
    fn escape_like_pattern_preserves_other_chars() {
        // Only the three metacharacters get escaped — everything else
        // is emitted verbatim, including unicode.
        assert_eq!(escape_like_pattern("héllo"), "héllo");
        assert_eq!(escape_like_pattern("a/b-c.d"), "a/b-c.d");
    }
}
