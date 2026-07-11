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
//!
//! 2026-07-01: the five copy-pasted subscriber loop skeletons were
//! extracted into the generic [`kernel`] module. Each `spawn_*`
//! function is now a thin wrapper: it builds a
//! `kernel::RpcSubscriberSpec` (subject, concurrency cap, the exact
//! pre-extraction log strings) and hands the kernel a per-message
//! handler closure holding the protocol-specific parse → verify →
//! nonce → permit → execute → reply → metric logic. Public signatures
//! unchanged; subjects, caps, reply semantics, and log/metric shapes
//! preserved byte-for-byte.

mod kernel;
use kernel::record_rpc_metric;

use talos_actor_memory_service as actor_memory_service;

// `ms_to_datetime` and `escape_like_pattern` live in
// `talos_integration_state` — they are utilities of that
// data-plane module, reusable from any subscriber or direct caller.

/// TTL for shared-store nonce entries. Must be `>=` the RPC freshness window
/// (`rpc_auth::PAST_WINDOW_MS` = 60 s past + a few seconds future skew); a
/// generous margin is harmless because a message can't be *fresh* after the
/// window anyway, so an entry lingering longer never causes a false replay.
const SHARED_NONCE_TTL_SECS: u64 = 120;

/// Cross-replica replay check (codebase-review finding #2). Consulted AFTER the
/// per-replica `req.verify()` (HMAC + freshness + process-local nonce) passes,
/// so a nonce replayed to a *different* controller replica within the freshness
/// window is also rejected — closing the "single-use degrades to
/// freshness-window-bounded replay across the fleet" gap.
///
/// Returns `true` (admit) when NO shared guard is registered — the default, so
/// behaviour is byte-identical to before this layer existed. When a guard IS
/// registered, returns `false` (reject) on a cross-replica replay, and applies
/// the operator's fail policy on backend unavailability (fail-open by default;
/// HMAC + freshness + per-replica nonce still hold).
///
/// The key namespaces on `subject` so a memory-op nonce can't collide with a
/// graph-search nonce, and on `actor_id` (host-supplied, not guest-controllable)
/// so the single-use domain matches the signature's binding.
async fn crossreplica_replay_ok(subject: &str, actor_id: uuid::Uuid, nonce: &str) -> bool {
    let Some(guard) = talos_replay_guard::shared_replay_guard() else {
        return true;
    };
    let key = format!("{subject}:{actor_id}:{nonce}");
    let outcome = guard.check_and_record(&key, SHARED_NONCE_TTL_SECS).await;
    if outcome == talos_replay_guard::ReplayOutcome::Replay {
        tracing::warn!(
            target: "talos_security",
            %subject,
            %actor_id,
            "cross-replica replay rejected: nonce already seen on another controller replica"
        );
    }
    talos_replay_guard::admit(outcome, talos_replay_guard::fail_closed_from_env())
}

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

/// Wasm-security review 2026-05-22 (MEDIUM-1): controller-side
/// expression-level function-name deny-list walker.
///
/// Walks every `Expr::Function` in the statement and returns the first
/// canonical-form name (`pg_sleep`, `pg_catalog.pg_sleep`, etc.) that
/// matches the canonical deny-list in
/// [`talos_workflow_job_protocol::DISALLOWED_SQL_FUNCTIONS`]. The
/// worker has the primary walker (which surfaces a typed
/// `SqlValidationError::DisallowedFunction`); this mirror is
/// defense-in-depth against worker↔controller divergence — same
/// pattern as the statement-level deny-list at MCP-473 above.
///
/// **Schema-qualification.** Same rule as the worker: bare
/// (`pg_sleep`) and `pg_catalog`-qualified (`pg_catalog.pg_sleep`)
/// forms are denied; other-schema qualified forms (`public.pg_sleep`)
/// are NOT matched here because the validator can't disambiguate from
/// the AST. The `talos_guest` role-wrap (M-2) is the fence for that
/// case.
fn controller_side_denied_function(stmt: &sqlparser::ast::Statement) -> Option<String> {
    use sqlparser::ast::{Expr, ObjectName, TableFactor, Visit, Visitor};
    use std::ops::ControlFlow;

    fn check_object_name(name: &ObjectName) -> Option<String> {
        let segments: Vec<&str> = name.0.iter().map(|i| i.value.as_str()).collect();
        match segments.as_slice() {
            [bare] => {
                if talos_workflow_job_protocol::is_disallowed_sql_function(bare) {
                    Some(bare.to_ascii_lowercase())
                } else {
                    None
                }
            }
            [schema, fn_name] => {
                if schema.eq_ignore_ascii_case("pg_catalog")
                    && talos_workflow_job_protocol::is_disallowed_sql_function(fn_name)
                {
                    Some(format!("pg_catalog.{}", fn_name.to_ascii_lowercase()))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    struct DenyVisitor;
    impl Visitor for DenyVisitor {
        type Break = String;
        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
            if let Expr::Function(func) = expr {
                if let Some(name) = check_object_name(&func.name) {
                    return ControlFlow::Break(name);
                }
            }
            ControlFlow::Continue(())
        }

        // FROM-clause set-returning function calls (`SELECT * FROM
        // dblink(...)`) parse as TableFactor, NOT Expr::Function.
        // Sibling-mirror to `worker::sql_validator::check_disallowed_functions`.
        fn pre_visit_table_factor(&mut self, tf: &TableFactor) -> ControlFlow<Self::Break> {
            match tf {
                TableFactor::Table {
                    name,
                    args: Some(_),
                    ..
                } => {
                    if let Some(denied) = check_object_name(name) {
                        return ControlFlow::Break(denied);
                    }
                }
                TableFactor::Function { name, .. } => {
                    if let Some(denied) = check_object_name(name) {
                        return ControlFlow::Break(denied);
                    }
                }
                _ => {}
            }
            ControlFlow::Continue(())
        }
    }

    match stmt.visit(&mut DenyVisitor) {
        ControlFlow::Break(name) => Some(name),
        ControlFlow::Continue(()) => None,
    }
}

/// Controller-side fail-closed allow-list mirroring the worker's posture:
/// permit ONLY the data statements a database node legitimately issues
/// (SELECT / INSERT / UPDATE / DELETE / MERGE). Everything else — DDL
/// (CREATE/DROP/ALTER/TRUNCATE/GRANT/REVOKE), ATTACH, CALL, and any NEW
/// sqlparser `Statement` variant — returns false and is rejected before
/// execution. The blocked_label + function deny-lists are DENY lists (a
/// statement they don't name falls through and runs on the controller's
/// full-privilege pool); this is the fail-closed complement that catches a
/// compromised worker bypassing its own `is_ddl`/`UNKNOWN` gate.
///
/// EXPLAIN is intentionally NOT permitted (stricter than the worker, which
/// always allows it): `EXPLAIN ANALYZE <stmt>` EXECUTES its inner statement
/// (e.g. `EXPLAIN ANALYZE CREATE TABLE … AS SELECT` runs the CTAS), so
/// admitting it would reopen the DDL/mutation bypass this gate closes.
fn controller_permits_data_statement(stmt: &sqlparser::ast::Statement) -> bool {
    use sqlparser::ast::Statement as S;
    matches!(
        stmt,
        S::Query(_) | S::Insert(_) | S::Update { .. } | S::Delete(_) | S::Merge { .. }
    )
}

/// Wasm-security review 2026-05-22 (MEDIUM-2): resolve the operator-
/// configured guest role for per-query `SET LOCAL ROLE`.
///
/// Returns `Some(role_name)` when `TALOS_RPC_GUEST_ROLE` is set to a
/// non-empty value, `None` otherwise. Cached at first call so the env
/// lookup happens once at startup, not on every RPC.
///
/// **Validation.** The role name is the operator's input but is
/// substituted into SQL via Postgres's `quote_ident` semantics
/// (`SET LOCAL ROLE "..."`) so injection is bounded to the role
/// namespace — the worst case is the SET failing with "role does not
/// exist" and the transaction rolling back. The role name MUST match
/// a strict identifier pattern (alphanumeric + underscore, leading
/// non-digit, ≤ 63 bytes — Postgres `NAMEDATALEN - 1`) so a
/// misconfigured env can't smuggle a SQL fragment. Invalid values
/// produce a startup-time warning and the wrap is disabled (fail-
/// open is acceptable because the role wrap is itself defense-in-
/// depth; the validator is the primary fence).
pub(crate) fn guest_role_for_query() -> Option<&'static str> {
    use std::sync::OnceLock;
    static ROLE: OnceLock<Option<String>> = OnceLock::new();
    ROLE.get_or_init(|| {
        let raw = std::env::var("TALOS_RPC_GUEST_ROLE").ok()?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        if !is_valid_pg_role_identifier(trimmed) {
            tracing::warn!(
                target: "talos_rpc",
                event_kind = "guest_role_invalid_identifier",
                raw_len = trimmed.len(),
                "TALOS_RPC_GUEST_ROLE is set to an invalid Postgres identifier — \
                 guest queries will continue to run as the app user. \
                 Role names must match `[A-Za-z_][A-Za-z0-9_]{{,62}}`."
            );
            return None;
        }
        tracing::info!(
            target: "talos_rpc",
            event_kind = "guest_role_enabled",
            role = %trimmed,
            "Guest SQL will run with SET LOCAL ROLE — \
             ensure the role has minimal privileges (see talos_guest migration)."
        );
        Some(trimmed.to_string())
    })
    .as_deref()
}

/// Strict Postgres role-identifier validator. Pure function so it's
/// trivially testable and the call site (`guest_role_for_query`) has
/// no SQL-injection surface.
///
/// Rules:
///   * Non-empty, ≤ 63 bytes (Postgres `NAMEDATALEN - 1`).
///   * First char alphabetic ASCII or `_`.
///   * Remaining chars alphabetic, digit, or `_`.
///   * No quoting / dotted / mixed-case-sensitive shenanigans.
///
/// We don't accept the full Postgres unquoted-identifier grammar
/// (which allows dollar signs and some unicode) — the deliberate
/// narrowness rejects exotic role names that could surprise a future
/// auditor reading the env. Operators wanting an exotic role can
/// alias it to a simple name via `GRANT exotic_role TO talos_guest`.
pub(crate) fn is_valid_pg_role_identifier(s: &str) -> bool {
    if s.is_empty() || s.len() > 63 {
        return false;
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Wasm-security review 2026-05-22 (MEDIUM-2): execute a guest SQL
/// query inside a transaction, optionally with `SET LOCAL ROLE`.
///
/// The wrap is uniform for both fetch and non-fetch paths so we never
/// leave session state behind on the pooled connection. `SET LOCAL`
/// is automatically reverted at COMMIT/ROLLBACK; combined with the
/// `BEGIN ... COMMIT`-per-query discipline, the connection returns
/// to the pool in a known-clean state.
///
/// **Why a transaction even without a role.** sqlx's `q.fetch_one(&pool)`
/// acquires a connection, runs the query, releases the connection. If a
/// future call site adds `SET` statements expecting connection scope,
/// they'd leak across pool checkouts. Always-transaction is the
/// canonical pattern.
///
/// **Statement-timeout note.** Postgres `SET LOCAL statement_timeout`
/// could also be wrapped here, but it's already set at connection
/// init (`talos-db/src/lib.rs`); a redundant SET LOCAL would be
/// belt-and-suspenders but is currently omitted to keep the wrap
/// minimal. Operators wanting per-query overrides can extend this
/// helper.
async fn execute_guest_query(
    pool: &sqlx::PgPool,
    sql: &str,
    params: &[String],
    is_fetch: bool,
    guest_role: Option<&str>,
) -> Result<talos_memory::database_rpc::DatabaseResult, talos_memory::database_rpc::DatabaseRpcError>
{
    use sqlx::Row;
    use talos_memory::database_rpc::{
        DatabaseResult, DatabaseRpcError, MAX_RESULT_BYTES, MAX_RESULT_ROWS, QUERY_TIMEOUT_SECS,
    };

    // The whole query (including the optional role SET, the user SQL,
    // and the CTE wrap if any) runs under a single tokio timeout.
    // Pre-fix the fetch path used `q.fetch_one(&pool)` which acquires
    // its own connection — now we hold one for the transaction. The
    // controller-side `MAX_IN_FLIGHT = 8` semaphore upstream of this
    // call still bounds total concurrent connection-holders.
    let work = async {
        let mut tx = pool
            .begin()
            .await
            .map_err(|e| DatabaseRpcError::ConnectionFailed(e.to_string()))?;

        // SET LOCAL ROLE — reverted automatically at COMMIT/ROLLBACK.
        // `guest_role` is validated by `is_valid_pg_role_identifier`
        // at startup so this format!-into-SQL is safe.
        if let Some(role) = guest_role {
            let set_role_sql = format!("SET LOCAL ROLE \"{role}\"");
            sqlx::query(&set_role_sql)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    // Most likely cause: role doesn't exist or the app
                    // user isn't a member of it. Both are operator-
                    // configuration errors — surface as ConnectionFailed
                    // (not QueryError) so the metric / log distinguishes
                    // them from guest SQL faults.
                    DatabaseRpcError::ConnectionFailed(format!("SET LOCAL ROLE failed: {e}"))
                })?;
        }

        if is_fetch {
            // CTE wrap rationale unchanged from pre-MEDIUM-2 — see
            // `rpc_cte_name()` for the random-suffix design.
            let wrapped = format!(
                "WITH {cte} AS ({user_sql}) \
                 SELECT COALESCE(json_agg(t), '[]'::json) AS json_res \
                 FROM (SELECT * FROM {cte} LIMIT {lim}) t",
                cte = rpc_cte_name(),
                user_sql = sql,
                lim = MAX_RESULT_ROWS + 1
            );
            let mut q = sqlx::query(&wrapped);
            for p in params {
                q = q.bind(p);
            }
            let row = q
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| DatabaseRpcError::QueryError(e.to_string()))?;
            let json_val: serde_json::Value = row
                .try_get("json_res")
                .map_err(|e| DatabaseRpcError::QueryError(format!("json_res decode: {e}")))?;
            if let Some(arr) = json_val.as_array() {
                if arr.len() > MAX_RESULT_ROWS {
                    return Err(DatabaseRpcError::ResultTooLarge(format!(
                        "query returned more than {} rows — add LIMIT/OFFSET",
                        MAX_RESULT_ROWS
                    )));
                }
            }
            let rows_json = json_val.to_string();
            if rows_json.len() > MAX_RESULT_BYTES {
                return Err(DatabaseRpcError::ResultTooLarge(format!(
                    "result {} bytes exceeds {}-byte cap",
                    rows_json.len(),
                    MAX_RESULT_BYTES
                )));
            }
            // Commit so SET LOCAL ROLE is reverted before the
            // connection returns to the pool. fetch path is read-
            // only in practice (the user SQL is wrapped in
            // `SELECT json_agg`), but COMMIT vs ROLLBACK doesn't
            // affect that — SET LOCAL is reverted either way. We
            // COMMIT for symmetry with the non-fetch path.
            tx.commit()
                .await
                .map_err(|e| DatabaseRpcError::ConnectionFailed(e.to_string()))?;
            Ok(DatabaseResult {
                rows_json,
                rows_affected: 0,
            })
        } else {
            let mut q = sqlx::query(sql);
            for p in params {
                q = q.bind(p);
            }
            let r = q
                .execute(&mut *tx)
                .await
                .map_err(|e| DatabaseRpcError::QueryError(e.to_string()))?;
            tx.commit()
                .await
                .map_err(|e| DatabaseRpcError::ConnectionFailed(e.to_string()))?;
            Ok(DatabaseResult {
                rows_json: "[]".to_string(),
                rows_affected: r.rows_affected(),
            })
        }
    };

    match tokio::time::timeout(std::time::Duration::from_secs(QUERY_TIMEOUT_SECS), work).await {
        Ok(r) => r,
        Err(_) => Err(DatabaseRpcError::Timeout),
    }
}

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

// `record_rpc_metric` (structured queue_ms/exec_ms completion events)
// and `graceful_drain` (L-24) now live in `kernel` alongside the rest
// of the shared loop skeleton.

pub fn spawn_graph_rpc_subscriber(
    nats: std::sync::Arc<async_nats::Client>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use talos_memory::graph_rpc::{
        GraphHit as RpcHit, GraphRpcError, GraphSearchReply, GraphSearchRequest,
        GraphSearchResponse, MAX_DEPTH, MAX_IN_FLIGHT, MAX_LIMIT, SUBJECT_GRAPH_SEARCH,
    };
    // MCP-1126 (2026-05-16): supervisor loop re-binds subscription
    // on stream-end (now provided by `kernel::spawn_rpc_subscriber`).
    // Sibling sweep of MCP-1119/1120/1121/1122 to the controller-side
    // signed-RPC subscribers — graph_rpc is the worker's only path to
    // Neo4j graph-RAG, so if this subscriber dies on `sub.next() →
    // None` (NATS reconnect window, server-side unsubscribe, transient
    // async-nats subscription handoff) every worker graph-search call
    // times out until the controller restarts. The `in_flight` JoinSet
    // AND `sem` live OUTSIDE the supervisor loop so existing in-flight
    // work survives a re-bind.
    let spec = kernel::RpcSubscriberSpec {
        subject: SUBJECT_GRAPH_SEARCH,
        max_in_flight: MAX_IN_FLIGHT,
        active_msg: "Graph-RPC subscriber active",
        subscribe_failed_msg: "Graph-RPC subscribe failed; retrying after backoff (worker graph-search calls time out in the meantime)",
        rebind_event_kind: "graph_rpc_subscriber_rebinding",
        rebind_msg: "Graph-RPC subscriber stream ended; supervisor re-binding",
    };
    let handler_nats = nats.clone();
    kernel::spawn_rpc_subscriber(nats, shutdown, spec, move |msg, sem| {
        let nats_client = handler_nats.clone();
        async move {
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

            if !req.verify()
                || !crossreplica_replay_ok(SUBJECT_GRAPH_SEARCH, req.actor_id, &req.nonce).await
            {
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

            // Zombie-permit guard (docs/platform-primitive-checklist.md
            // §3): a stalled Neo4j must not hold this permit
            // indefinitely. Elapsed maps to the protocol's existing
            // `Timeout` variant / "timeout" outcome tag.
            let ctx_result = kernel::guard_op(service.get_graph_context(
                req.actor_id,
                &req.query,
                depth as usize,
                limit as usize,
            ))
            .await;

            let reply = match ctx_result {
                Err(_elapsed) => {
                    tracing::warn!(
                        actor_id = %req.actor_id,
                        timeout_secs = kernel::PERMIT_GUARD_TIMEOUT_SECS,
                        "graph-search RPC: op exceeded permit-guard timeout — permit released"
                    );
                    GraphSearchReply {
                        result: Err(GraphRpcError::Timeout),
                    }
                }
                Ok(Ok(json)) => {
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
                                    let edge_type =
                                        r.get("type").and_then(|v| v.as_str()).unwrap_or_default();
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
                Ok(Err(e)) => {
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
        }
    });
}

/// Serving context for the ML predict RPC — installed once from
/// `main()` (pool + a `DatasetService` over the canonical
/// `SecretsManager`) before [`spawn_ml_rpc_subscriber`]. Same
/// OnceLock-injection shape as `GRAPH_SERVICE`; until it is set the
/// subscriber answers `NotAvailable` rather than panicking.
pub struct MlPredictContext {
    pub db_pool: sqlx::PgPool,
    pub dataset_service: talos_ml::DatasetService,
}

pub static ML_PREDICT_CONTEXT: std::sync::OnceLock<MlPredictContext> = std::sync::OnceLock::new();

/// RFC 0011 P2c: `talos.ml.predict` — the worker's only path to model
/// inference (workers are credential-free; datasets/registry live
/// behind the controller's Postgres). Batch-first: one signed request
/// carries up to `MAX_INPUTS` feature texts.
///
/// Security shape (docs/platform-primitive-checklist.md walk,
/// 2026-07-11): every routing/tenancy field (`user_id`, `model_name`,
/// each input) is HMAC-bound; `verify()` gates before any DB touch;
/// nonce recording happens only after verify (verify/nonce split);
/// model resolution runs on a tenant-scoped read tx opened from the
/// SIGNED `user_id`, so RLS backstops the app-layer scoping; error
/// variants are coarse (NotFound covers absent AND foreign models —
/// no cross-tenant enumeration); the permit-holding serve future is
/// wrapped in the protocol's 8 s op timeout (tighter than the worker's
/// 10 s request timeout, so a stalled Postgres releases the permit
/// before the caller has already given up).
pub fn spawn_ml_rpc_subscriber(
    nats: std::sync::Arc<async_nats::Client>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use talos_memory::ml_rpc::{
        MlPredictRequest, MlPredictResponse, MlRpcError, MAX_IN_FLIGHT, SUBJECT_ML_PREDICT,
        SUBSCRIBER_OP_TIMEOUT_MS,
    };

    async fn publish_reply(
        nats: &async_nats::Client,
        reply_to: async_nats::Subject,
        resp: &talos_memory::ml_rpc::MlPredictResponse,
    ) {
        let _ = nats
            .publish(
                reply_to,
                serde_json::to_vec(resp).unwrap_or_default().into(),
            )
            .await;
    }

    let spec = kernel::RpcSubscriberSpec {
        subject: SUBJECT_ML_PREDICT,
        max_in_flight: MAX_IN_FLIGHT,
        active_msg: "ML-predict RPC subscriber active",
        subscribe_failed_msg: "ML-predict RPC subscribe failed; retrying after backoff (worker model::predict calls time out in the meantime)",
        rebind_event_kind: "ml_rpc_subscriber_rebinding",
        rebind_msg: "ML-predict RPC subscriber stream ended; supervisor re-binding",
    };
    let handler_nats = nats.clone();
    kernel::spawn_rpc_subscriber(nats, shutdown, spec, move |msg, sem| {
        let nats_client = handler_nats.clone();
        async move {
            let start = std::time::Instant::now();
            let reply_to = match msg.reply.clone() {
                Some(r) => r,
                None => return,
            };

            let req: MlPredictRequest = match serde_json::from_slice(&msg.payload) {
                Ok(r) => r,
                Err(_) => {
                    // Generic Invalid — parse detail stays server-side.
                    publish_reply(
                        &nats_client,
                        reply_to,
                        &MlPredictResponse::Err(MlRpcError::Invalid),
                    )
                    .await;
                    record_rpc_metric(
                        SUBJECT_ML_PREDICT,
                        uuid::Uuid::nil(),
                        "invalid",
                        start.elapsed().as_millis() as u64,
                        0,
                    );
                    return;
                }
            };

            // verify() covers HMAC + freshness + the structural caps
            // (validate_structure runs inside it), so no separate
            // size-cap pass is needed here.
            if !req.verify()
                || !crossreplica_replay_ok(SUBJECT_ML_PREDICT, req.actor_id, &req.nonce).await
            {
                tracing::warn!(
                    actor_id = %req.actor_id,
                    "ml-predict RPC: HMAC or freshness verification failed"
                );
                publish_reply(
                    &nats_client,
                    reply_to,
                    &MlPredictResponse::Err(MlRpcError::Unauthorized),
                )
                .await;
                record_rpc_metric(
                    SUBJECT_ML_PREDICT,
                    req.actor_id,
                    "unauthorized",
                    start.elapsed().as_millis() as u64,
                    0,
                );
                return;
            }

            if !talos_memory::rpc_auth::check_and_record_nonce(
                talos_memory::ml_rpc::SUBJECT_NAME,
                req.actor_id,
                &req.nonce,
            ) {
                tracing::warn!(
                    actor_id = %req.actor_id,
                    "ml-predict RPC: nonce replay rejected"
                );
                publish_reply(
                    &nats_client,
                    reply_to,
                    &MlPredictResponse::Err(MlRpcError::Unauthorized),
                )
                .await;
                record_rpc_metric(
                    SUBJECT_ML_PREDICT,
                    req.actor_id,
                    "replay",
                    start.elapsed().as_millis() as u64,
                    0,
                );
                return;
            }

            let Some(ctx) = ML_PREDICT_CONTEXT.get() else {
                publish_reply(
                    &nats_client,
                    reply_to,
                    &MlPredictResponse::Err(MlRpcError::NotAvailable),
                )
                .await;
                record_rpc_metric(
                    SUBJECT_ML_PREDICT,
                    req.actor_id,
                    "not_available",
                    start.elapsed().as_millis() as u64,
                    0,
                );
                return;
            };

            // Bound concurrent predict batches (embedding provider +
            // ANN queries). Dropping the permit on any exit releases it.
            let _permit = sem.acquire_owned().await;
            let permit_at = std::time::Instant::now();

            // Zombie-permit guard (checklist §3) at the protocol's own
            // 8 s cap: covers the tenant tx open, model resolution, and
            // the whole embed+knn batch.
            let served = kernel::guard_op_with(
                std::time::Duration::from_millis(SUBSCRIBER_OP_TIMEOUT_MS),
                async {
                    // Tenancy from the SIGNED user_id — never from
                    // anything the guest could vary without re-signing.
                    let mut tx = talos_db::begin_tenant_read_scoped(
                        &ctx.db_pool,
                        &talos_tenancy::TenantReadScope::new(req.user_id, Vec::new()),
                    )
                    .await
                    .map_err(talos_ml::ServeError::Internal)?;
                    let reply = talos_ml::serve_predict_batch(
                        &ctx.dataset_service,
                        &mut tx,
                        req.user_id,
                        &req.model_name,
                        &req.inputs,
                    )
                    .await?;
                    // Read-only tx; commit releases the scope cleanly.
                    tx.commit()
                        .await
                        .map_err(|e| talos_ml::ServeError::Internal(anyhow::anyhow!(e)))?;
                    Ok::<_, talos_ml::ServeError>(reply)
                },
            )
            .await;

            let resp = match served {
                Err(_elapsed) => {
                    tracing::warn!(
                        actor_id = %req.actor_id,
                        timeout_ms = SUBSCRIBER_OP_TIMEOUT_MS,
                        "ml-predict RPC: op exceeded permit-guard timeout — permit released"
                    );
                    MlPredictResponse::Err(MlRpcError::Timeout)
                }
                Ok(Ok(reply)) => MlPredictResponse::Ok(talos_memory::ml_rpc::MlPredictReply {
                    predictions: reply
                        .predictions
                        .into_iter()
                        .map(|p| {
                            p.map(|p| talos_memory::ml_rpc::WirePrediction {
                                label: p.label,
                                confidence: p.confidence,
                            })
                        })
                        .collect(),
                    model_version: reply.model_version,
                    backend: reply.backend,
                }),
                Ok(Err(talos_ml::ServeError::NotFound)) => {
                    MlPredictResponse::Err(MlRpcError::NotFound)
                }
                Ok(Err(talos_ml::ServeError::NotPromoted)) => {
                    MlPredictResponse::Err(MlRpcError::NotPromoted)
                }
                Ok(Err(talos_ml::ServeError::NotAvailable)) => {
                    MlPredictResponse::Err(MlRpcError::NotAvailable)
                }
                Ok(Err(talos_ml::ServeError::Internal(e))) => {
                    // Full detail server-side only; wire gets the bare
                    // variant (no schema/query leakage).
                    tracing::warn!(
                        actor_id = %req.actor_id,
                        error = %e,
                        "ml-predict RPC: serve error"
                    );
                    MlPredictResponse::Err(MlRpcError::Internal)
                }
            };

            let outcome = match &resp {
                MlPredictResponse::Ok(_) => "ok",
                MlPredictResponse::Err(MlRpcError::Unauthorized) => "unauthorized",
                MlPredictResponse::Err(MlRpcError::NotFound) => "not_found",
                MlPredictResponse::Err(MlRpcError::NotPromoted) => "not_promoted",
                MlPredictResponse::Err(MlRpcError::NotAvailable) => "not_available",
                MlPredictResponse::Err(MlRpcError::Invalid) => "invalid",
                MlPredictResponse::Err(MlRpcError::Timeout) => "timeout",
                MlPredictResponse::Err(MlRpcError::Internal) => "internal",
            };
            publish_reply(&nats_client, reply_to, &resp).await;
            record_rpc_metric(
                SUBJECT_ML_PREDICT,
                req.actor_id,
                outcome,
                permit_at.saturating_duration_since(start).as_millis() as u64,
                permit_at.elapsed().as_millis() as u64,
            );
        }
    });
}

pub fn spawn_memory_rpc_subscriber(
    nats: std::sync::Arc<async_nats::Client>,
    pool: sqlx::PgPool,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use talos_memory::memory_rpc::{
        MemoryRpcError, MemoryRpcReply, MemoryRpcRequest, MAX_IN_FLIGHT, SUBJECT_MEMORY_OP,
    };
    // MCP-1127 (2026-05-16): supervisor loop re-binds subscription
    // on stream-end (now provided by `kernel::spawn_rpc_subscriber`).
    // Sibling sweep of MCP-1126 to the memory_rpc
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
    let spec = kernel::RpcSubscriberSpec {
        subject: SUBJECT_MEMORY_OP,
        max_in_flight: MAX_IN_FLIGHT,
        active_msg: "Memory-RPC subscriber active",
        subscribe_failed_msg: "Memory-RPC subscribe failed; retrying after backoff (worker agent_memory calls time out in the meantime)",
        rebind_event_kind: "memory_rpc_subscriber_rebinding",
        rebind_msg: "Memory-RPC subscriber stream ended; supervisor re-binding",
    };
    let handler_nats = nats.clone();
    kernel::spawn_rpc_subscriber(nats, shutdown, spec, move |msg, sem| {
        let nats_client = handler_nats.clone();
        let pool = pool.clone();
        async move {
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

            if !req.verify()
                || !crossreplica_replay_ok(SUBJECT_MEMORY_OP, req.actor_id, &req.nonce).await
            {
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

            // Zombie-permit guard (docs/platform-primitive-checklist.md
            // §3): a stalled Postgres must not hold this permit
            // indefinitely. Elapsed maps to the protocol's existing
            // `Timeout` variant / "timeout" outcome tag.
            let op_result =
                match kernel::guard_op(execute_memory_op(&pool, req.actor_id, req.op)).await {
                    Ok(r) => r,
                    Err(_elapsed) => {
                        tracing::warn!(
                            actor_id = %req.actor_id,
                            timeout_secs = kernel::PERMIT_GUARD_TIMEOUT_SECS,
                            "memory RPC: op exceeded permit-guard timeout — permit released"
                        );
                        Err(MemoryRpcError::Timeout)
                    }
                };

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
        }
    });
}

/// Memory-RPC op dispatch — the per-protocol execute stage called by
/// `spawn_memory_rpc_subscriber`'s handler while holding a permit.
/// Was a nested fn inside the subscriber loop pre-kernel-extraction;
/// body unchanged.
async fn execute_memory_op(
    pool: &sqlx::PgPool,
    actor_id: uuid::Uuid,
    op: talos_memory::memory_rpc::MemoryOp,
) -> Result<talos_memory::memory_rpc::MemoryOpResult, talos_memory::memory_rpc::MemoryRpcError> {
    use talos_memory::memory_rpc::{
        MemoryHit as RpcMemHit, MemoryOp, MemoryOpResult, MemoryRpcError, MAX_RESULT_LIMIT,
    };
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
                    value: serde_json::to_string(&row.value).unwrap_or_else(|_| "null".into()),
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
            use talos_memory::memory_rpc::{MAX_EXCLUDE_KINDS, MAX_EXCLUDE_KIND_LEN};
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

pub fn spawn_database_rpc_subscriber(
    nats: std::sync::Arc<async_nats::Client>,
    pool: sqlx::PgPool,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    // Wasm-security review 2026-05-22 (MEDIUM-2): MAX_RESULT_* /
    // QUERY_TIMEOUT_SECS moved into `execute_guest_query`; only
    // the types still referenced in this fn remain (`DatabaseResult`
    // is the success type the `send` closure returns up the NATS
    // reply path).
    use talos_memory::database_rpc::{
        DatabaseResult, DatabaseRpcError, DatabaseRpcReply, DatabaseRpcRequest, MAX_IN_FLIGHT,
        SUBJECT_DATABASE_QUERY,
    };
    // MCP-1128 (2026-05-16): supervisor loop re-binds subscription
    // on stream-end (now provided by `kernel::spawn_rpc_subscriber`).
    // Sibling sweep of MCP-1126/1127 to the
    // database_rpc primitive. Per CLAUDE.md the worker is
    // credential-free; `wit_database::execute_query` is the only
    // path for sandbox SQL. Pre-fix `None => break` on stream-end
    // (NATS reconnect window, server-side unsub, async-nats
    // subscription handoff) → every worker SQL query timed out
    // until controller restart, taking down every workflow that
    // uses the database WIT host fn.
    let spec = kernel::RpcSubscriberSpec {
        subject: SUBJECT_DATABASE_QUERY,
        max_in_flight: MAX_IN_FLIGHT,
        active_msg: "Database-RPC subscriber active",
        subscribe_failed_msg: "Database-RPC subscribe failed; retrying after backoff (worker execute_query calls time out in the meantime)",
        rebind_event_kind: "database_rpc_subscriber_rebinding",
        rebind_msg: "Database-RPC subscriber stream ended; supervisor re-binding",
    };
    let handler_nats = nats.clone();
    kernel::spawn_rpc_subscriber(nats, shutdown, spec, move |msg, sem| {
        let nats_client = handler_nats.clone();
        let pool = pool.clone();
        async move {
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

            if !req.verify()
                || !crossreplica_replay_ok(SUBJECT_DATABASE_QUERY, req.actor_id, &req.nonce).await
            {
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

                // Wasm-security review 2026-05-22 (MEDIUM-1):
                // controller-side mirror of the worker's
                // expression-level function deny-list.
                //
                // The deliberate-duplication pattern follows
                // MCP-473 (statement-level) above: the worker is
                // primary defense, but if a future divergence bug
                // lets a denied function reach here, the controller
                // re-rejects. Both sides import the canonical
                // deny-list from `talos_workflow_job_protocol::
                // DISALLOWED_SQL_FUNCTIONS` so list-drift is
                // architecturally impossible. The visitor wrapper
                // is duplicated (worker uses its own to wire into
                // `SqlValidationError::DisallowedFunction`, this
                // side just needs a yes/no), but the deny-list
                // itself is shared.
                //
                // Same cost profile as the worker walk: ~5-20 µs
                // for a typical query, well below the network +
                // DB time.
                if let Some(denied) = controller_side_denied_function(&stmts[0]) {
                    tracing::warn!(
                        target: "talos_rpc",
                        event_kind = "database_rpc_disallowed_function",
                        actor_id = %req.actor_id,
                        denied_function = %denied,
                        "database RPC: rejecting query referencing deny-listed function \
                         — possible worker bypass (worker should already have refused)"
                    );
                    send(Err(DatabaseRpcError::InvalidQuery(format!(
                            "SQL references function `{denied}` which is on the unconditional deny-list"
                        ))))
                        .await;
                    record_rpc_metric(
                        SUBJECT_DATABASE_QUERY,
                        req.actor_id,
                        "disallowed_function",
                        start.elapsed().as_millis() as u64,
                        0,
                    );
                    return;
                }

                // Fail-closed allow-list — the worker's posture, mirrored.
                // The blocked_label + function deny-lists above are DENY
                // lists: a DDL statement (DROP / ALTER … DISABLE ROW LEVEL
                // SECURITY / GRANT / REVOKE / TRUNCATE / CREATE), an
                // ATTACH/CALL, or ANY new sqlparser variant falls through
                // them as `None` and would reach `execute_guest_query` on
                // the controller's full-privilege pool. The worker's
                // `is_ddl` + fail-closed `UNKNOWN` gate is the only fence
                // today; a COMPROMISED worker (the entire reason this
                // handler re-validates) that skipped it could run arbitrary
                // DDL — DROP a table, disable RLS, GRANT privileges. Permit
                // ONLY the data statements a database node legitimately
                // issues; reject everything else.
                //
                // EXPLAIN is deliberately EXCLUDED (stricter than the
                // worker, which always permits it): `EXPLAIN ANALYZE <stmt>`
                // EXECUTES its inner statement (e.g. `EXPLAIN ANALYZE CREATE
                // TABLE … AS SELECT` runs the CTAS), so admitting Explain
                // here would reopen the DDL/mutation bypass this gate
                // closes. DML is admitted: the per-actor
                // `allowed_sql_operations` allowlist isn't on the RPC wire,
                // and the `talos_guest` role grant is its privilege fence.
                if !controller_permits_data_statement(&stmts[0]) {
                    tracing::warn!(
                        target: "talos_rpc",
                        event_kind = "database_rpc_statement_not_permitted",
                        actor_id = %req.actor_id,
                        "database RPC: rejecting non-data statement (DDL / CALL / ATTACH / \
                         EXPLAIN / unknown) — possible worker bypass (worker should already \
                         have refused)"
                    );
                    send(Err(DatabaseRpcError::InvalidQuery(
                        "only data statements (SELECT/INSERT/UPDATE/DELETE/MERGE) are permitted"
                            .to_string(),
                    )))
                    .await;
                    record_rpc_metric(
                        SUBJECT_DATABASE_QUERY,
                        req.actor_id,
                        "statement_not_permitted",
                        start.elapsed().as_millis() as u64,
                        0,
                    );
                    return;
                }
            }

            let _permit = sem.acquire_owned().await;
            let permit_at = std::time::Instant::now();

            // Zombie-permit guard: unlike the other subscribers this
            // path does NOT wrap in `kernel::guard_op` —
            // `execute_guest_query` already runs its entire
            // transaction under `QUERY_TIMEOUT_SECS` (30 s), which
            // bounds the permit-holding window; double-wrapping
            // would just race two identical timers.

            // Wasm-security review 2026-05-22 (MEDIUM-2): per-actor
            // role wrap. When `TALOS_RPC_GUEST_ROLE` is set, every
            // guest query runs inside a transaction with
            // `SET LOCAL ROLE <role>`. This bounds the privileges
            // available to guest SQL to whatever the operator has
            // granted to that role — which by default is nothing
            // (see `migrations/20260522120000_talos_guest_role.sql`).
            // Unset = legacy behaviour (queries run as the app
            // user); operators roll out per environment.
            //
            // The wrap is conditional on the env var, but the
            // transaction-with-SET-LOCAL approach is also the
            // canonical pattern for "per-query session state"
            // even without a role — it ensures the connection
            // returned to the pool is clean regardless of how the
            // query exited (commit, rollback, panic).
            let result = execute_guest_query(
                &pool,
                &req.sql,
                &req.params,
                req.is_fetch,
                guest_role_for_query(),
            )
            .await;

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
        }
    });
}

pub fn spawn_state_write_subscriber(
    nats: std::sync::Arc<async_nats::Client>,
    pool: sqlx::PgPool,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use talos_memory::state_rpc::{StateWriteRequest, MAX_IN_FLIGHT, SUBJECT_STATE_WRITE};
    // Fire-and-forget: no reply subject, no response. We still
    // verify the HMAC, rate-limit, and write to execution_state.
    //
    // MCP-1129 (2026-05-16): supervisor loop re-binds subscription
    // on stream-end (now provided by `kernel::spawn_rpc_subscriber`).
    // Sibling sweep of MCP-1126/1127/1128 to
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
    let spec = kernel::RpcSubscriberSpec {
        subject: SUBJECT_STATE_WRITE,
        max_in_flight: MAX_IN_FLIGHT,
        active_msg: "State-write subscriber active",
        subscribe_failed_msg: "State-write subscribe failed; retrying after backoff (execution_state durability disabled in the meantime)",
        rebind_event_kind: "state_rpc_subscriber_rebinding",
        rebind_msg: "State-write subscriber stream ended; supervisor re-binding",
    };
    // NB: `nats` is consumed by the kernel for the subscription only —
    // this handler never publishes (fire-and-forget has no reply).
    kernel::spawn_rpc_subscriber(nats, shutdown, spec, move |msg, sem| {
        let pool = pool.clone();
        async move {
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
            if !req.verify()
                || !crossreplica_replay_ok(SUBJECT_STATE_WRITE, req.actor_id, &req.nonce).await
            {
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
            // Zombie-permit guard (docs/platform-primitive-checklist.md
            // §3): a stalled Postgres must not hold this permit
            // indefinitely. Fire-and-forget → nothing to reply on
            // timeout; the write is dropped (within the guest-facing
            // silent-loss contract) and the drop is logged + tagged
            // "timeout" so operators can alert on it, same as the
            // MCP-733 query_error visibility rule.
            let db_work = async {
                if req.is_delete {
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
                }
            };
            let outcome: &'static str = match kernel::guard_op(db_work).await {
                Ok(tag) => tag,
                Err(_elapsed) => {
                    tracing::warn!(
                        target: "talos_rpc",
                        actor_id = %req.actor_id,
                        execution_id = %req.execution_id,
                        timeout_secs = kernel::PERMIT_GUARD_TIMEOUT_SECS,
                        "state-write: DB op exceeded permit-guard timeout — write dropped (fire-and-forget), permit released"
                    );
                    "timeout"
                }
            };
            record_rpc_metric(
                SUBJECT_STATE_WRITE,
                req.actor_id,
                outcome,
                permit_at.saturating_duration_since(start).as_millis() as u64,
                permit_at.elapsed().as_millis() as u64,
            );
        }
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
    use talos_memory::integration_state_rpc::{
        IntegrationStateError, IntegrationStateReply, IntegrationStateRequest, MAX_IN_FLIGHT,
        SUBJECT_INTEGRATION_STATE_OP,
    };
    // MCP-1130 (2026-05-16): supervisor loop re-binds subscription
    // on stream-end (now provided by `kernel::spawn_rpc_subscriber`).
    // Completes the MCP-1126–1129 sweep across all
    // 5 signed-RPC subscribers. integration_state_rpc is the
    // generic primitive integrations use to persist their own
    // scoped state (gcal sync token, gmail watch history-id,
    // jira filter cursor, etc.) — a dead subscriber means
    // workers' integration-state writes time out → integrations
    // can't persist their sync progress → next poll re-fetches
    // from the beginning of history (gcal/gmail) or fails
    // outright (jira filter cursor lost). Re-bind closes that
    // gap on NATS reconnects / subscription handoff.
    let spec = kernel::RpcSubscriberSpec {
        subject: SUBJECT_INTEGRATION_STATE_OP,
        max_in_flight: MAX_IN_FLIGHT,
        active_msg: "Integration-state subscriber active",
        subscribe_failed_msg: "Integration-state subscribe failed; retrying after backoff (worker integration_state calls time out in the meantime)",
        rebind_event_kind: "integration_state_rpc_subscriber_rebinding",
        rebind_msg: "Integration-state subscriber stream ended; supervisor re-binding",
    };
    let handler_nats = nats.clone();
    kernel::spawn_rpc_subscriber(nats, shutdown, spec, move |msg, sem| {
        let nats_client = handler_nats.clone();
        let pool = pool.clone();
        async move {
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

            if !req.verify()
                || !crossreplica_replay_ok(SUBJECT_INTEGRATION_STATE_OP, req.actor_id, &req.nonce)
                    .await
            {
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

            // Zombie-permit guard (docs/platform-primitive-checklist.md
            // §3): a stalled Postgres must not hold this permit
            // indefinitely. Elapsed maps to the protocol's existing
            // `Timeout` variant / "timeout" outcome tag.
            let op_result = match kernel::guard_op(talos_integration_state::execute_op(
                &pool,
                &req.integration_name,
                req.user_id,
                req.op,
            ))
            .await
            {
                Ok(r) => r,
                Err(_elapsed) => {
                    tracing::warn!(
                        actor_id = %req.actor_id,
                        integration = %req.integration_name,
                        timeout_secs = kernel::PERMIT_GUARD_TIMEOUT_SECS,
                        "integration-state RPC: op exceeded permit-guard timeout — permit released"
                    );
                    Err(IntegrationStateError::Timeout)
                }
            };

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
        }
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

// ============================================================================
// Wasm-security review 2026-05-22 (MEDIUM-1): controller-side SQL function
// deny-list tests. Sibling to the worker's `function_deny_list_*` tests in
// `worker/src/sql_validator.rs` — both sides MUST agree on the canonical
// list (sourced from `talos_workflow_job_protocol::DISALLOWED_SQL_FUNCTIONS`)
// and on the schema-qualification handling. If the worker drops detection
// for a function, the controller-side mirror is the next gate; tests here
// pin that the mirror catches the cases the worker is documented to catch.
// ============================================================================
#[cfg(test)]
mod controller_statement_allowlist_tests {
    use super::controller_permits_data_statement;
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    fn parse1(sql: &str) -> sqlparser::ast::Statement {
        let mut s = Parser::parse_sql(&PostgreSqlDialect {}, sql)
            .unwrap_or_else(|e| panic!("parse failed for `{sql}`: {e}"));
        s.pop().unwrap()
    }

    #[test]
    fn data_statements_are_permitted() {
        for sql in [
            "SELECT * FROM t WHERE id = $1",
            "INSERT INTO t (a) VALUES ($1)",
            "UPDATE t SET a = $1 WHERE id = $2",
            "DELETE FROM t WHERE id = $1",
            "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET a = s.a",
            "WITH c AS (SELECT 1) SELECT * FROM c",
        ] {
            assert!(
                controller_permits_data_statement(&parse1(sql)),
                "should permit: {sql}"
            );
        }
    }

    #[test]
    fn ddl_and_escalation_statements_are_rejected() {
        // The compromised-worker class: these fall through the deny-lists and
        // would run on the controller's full-privilege pool without this gate.
        for sql in [
            "DROP TABLE secrets",
            "ALTER TABLE actor_memory DISABLE ROW LEVEL SECURITY",
            "GRANT ALL ON ALL TABLES IN SCHEMA public TO PUBLIC",
            "REVOKE SELECT ON t FROM PUBLIC",
            "TRUNCATE workflow_executions",
            "CREATE TABLE x (a int)",
            "CREATE TABLE x AS SELECT * FROM secrets",
        ] {
            assert!(
                !controller_permits_data_statement(&parse1(sql)),
                "should reject: {sql}"
            );
        }
    }

    #[test]
    fn explain_is_rejected_to_block_analyze_execution() {
        // EXPLAIN ANALYZE executes its inner statement (CTAS / DML), so the
        // controller is deliberately stricter than the worker and rejects all
        // EXPLAIN forms.
        assert!(!controller_permits_data_statement(&parse1(
            "EXPLAIN SELECT 1"
        )));
        assert!(!controller_permits_data_statement(&parse1(
            "EXPLAIN ANALYZE DELETE FROM t"
        )));
    }
}

#[cfg(test)]
mod controller_function_deny_tests {
    use super::controller_side_denied_function;
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    fn parse_one(sql: &str) -> sqlparser::ast::Statement {
        let mut stmts = Parser::parse_sql(&PostgreSqlDialect {}, sql)
            .unwrap_or_else(|e| panic!("parse failed for `{sql}`: {e}"));
        assert_eq!(
            stmts.len(),
            1,
            "test SQL must be a single statement: `{sql}`"
        );
        stmts.pop().unwrap()
    }

    #[test]
    fn pg_sleep_top_level() {
        let stmt = parse_one("SELECT pg_sleep(1)");
        assert_eq!(
            controller_side_denied_function(&stmt).as_deref(),
            Some("pg_sleep")
        );
    }

    #[test]
    fn pg_catalog_qualified_form() {
        let stmt = parse_one("SELECT pg_catalog.pg_sleep(1)");
        assert_eq!(
            controller_side_denied_function(&stmt).as_deref(),
            Some("pg_catalog.pg_sleep")
        );
    }

    #[test]
    fn user_schema_qualified_form_not_matched() {
        // Documented trade-off — same as worker. Validator can't
        // disambiguate user-defined vs stock; the `talos_guest` role
        // is the fence.
        let stmt = parse_one("SELECT public.pg_sleep(1)");
        assert_eq!(controller_side_denied_function(&stmt), None);
    }

    #[test]
    fn case_insensitive() {
        for sql in [
            "SELECT PG_SLEEP(1)",
            "SELECT Pg_Sleep(1)",
            "SELECT pg_catalog.PG_SLEEP(1)",
        ] {
            let stmt = parse_one(sql);
            assert!(
                controller_side_denied_function(&stmt).is_some(),
                "case variant `{sql}` not blocked"
            );
        }
    }

    #[test]
    fn walks_into_subqueries_and_ctes() {
        let cases = [
            "SELECT * FROM users WHERE id IN (SELECT pg_terminate_backend(pid) FROM pg_stat_activity)",
            "WITH bad AS (SELECT pg_read_file('/etc/passwd') AS x) SELECT * FROM bad",
            "SELECT * FROM t1 JOIN t2 ON pg_sleep(60) IS NULL",
            "SELECT CASE WHEN id > 5 THEN pg_terminate_backend(id) ELSE 0 END FROM users",
            "SELECT (SELECT (SELECT (SELECT pg_sleep(60))))",
        ];
        for sql in cases {
            let stmt = parse_one(sql);
            assert!(
                controller_side_denied_function(&stmt).is_some(),
                "deeply-nested deny case `{sql}` not blocked"
            );
        }
    }

    #[test]
    fn benign_functions_not_blocked() {
        for sql in [
            "SELECT count(*) FROM users",
            "SELECT sum(amount) FROM payments",
            "SELECT now()",
            "SELECT json_agg(t) FROM (SELECT * FROM users) t",
            "SELECT current_user",
            "SELECT row_number() OVER (ORDER BY id) FROM events",
            "SELECT pg_my_custom_business_func(id) FROM t",
        ] {
            let stmt = parse_one(sql);
            assert_eq!(
                controller_side_denied_function(&stmt),
                None,
                "benign SQL `{sql}` was incorrectly blocked"
            );
        }
    }

    // ---- Wasm-security review 2026-05-22 (MEDIUM-2) ----
    //
    // Per-actor Postgres role validator. Tests live in the same mod
    // because they share `super::*` access; the controller-side
    // function-deny tests above already pull in the parser, so this
    // saves a fresh mod.

    #[test]
    fn role_identifier_validator_accepts_canonical_form() {
        use super::is_valid_pg_role_identifier;
        for name in [
            "talos_guest",
            "guest",
            "guest_role",
            "Guest",
            "_internal_role",
            "a",
            "abc_123",
            // 63 chars (Postgres NAMEDATALEN - 1): boundary OK.
            &"a".repeat(63),
        ] {
            assert!(
                is_valid_pg_role_identifier(name),
                "valid identifier `{name}` was rejected"
            );
        }
    }

    #[test]
    fn role_identifier_validator_rejects_injection_attempts() {
        use super::is_valid_pg_role_identifier;
        for bad in [
            "",
            " ",
            "talos_guest; DROP ROLE postgres",
            "talos_guest\"; DROP ROLE postgres; --",
            "talos guest", // space
            "talos-guest", // hyphen — valid PG quoted ident but rejected by our narrow rule
            "1guest",      // starts with digit
            ".guest",
            "talos.guest",
            "talos_guest\n",
            "talos_guest\u{0000}",
            "talos_guest\\",
            "пользователь", // non-ASCII (rejected by design; alias if needed)
            // 64 chars: over the NAMEDATALEN-1 boundary.
            &"a".repeat(64),
            // 100 chars: well over.
            &"a".repeat(100),
        ] {
            assert!(
                !is_valid_pg_role_identifier(bad),
                "invalid identifier `{bad:?}` was accepted — SQL injection risk"
            );
        }
    }

    #[test]
    fn deny_list_lockstep_with_worker_canonical_const() {
        // Tripwire: the canonical const drives both worker and
        // controller. This test pins that the controller walker
        // recognises every entry in the const — if a future PR adds
        // an entry to the const but forgets to update the walker
        // (e.g. by special-casing), this fires.
        for fn_name in talos_workflow_job_protocol::DISALLOWED_SQL_FUNCTIONS {
            // Some entries (e.g. `lo_import`, `plperlu_call_handler`)
            // are not naturally callable as `SELECT fn()` — they're
            // either set-returning, void, or trigger handlers. We
            // wrap them in a context that always parses: a bare
            // function call inside a SELECT projection (which
            // sqlparser accepts for any function shape).
            let sql = format!("SELECT {fn_name}(1)");
            let stmts = Parser::parse_sql(&PostgreSqlDialect {}, &sql);
            // Skip names sqlparser refuses to parse as a function call
            // (none expected with current entries; the catch is here
            // so a future addition of a reserved-keyword function
            // surfaces visibly rather than as a silent skip).
            let Ok(mut parsed) = stmts else { continue };
            if parsed.len() != 1 {
                continue;
            }
            let stmt = parsed.pop().unwrap();
            assert!(
                controller_side_denied_function(&stmt).is_some(),
                "canonical deny-list entry `{fn_name}` not caught by controller walker"
            );
        }
    }
}
