//! `database` host interface (signed NATS-RPC to the controller;
//! SQL validation via `sql_validator`).

use super::*;

// ============================================================================
// Database (placeholder — enforce row-level scoping in production)
// ============================================================================

impl wit_database::Host for TalosContext {
    #[::tracing::instrument(name = "database.query", skip_all, fields(param_count = params.len()))]
    async fn execute_query(
        &mut self,
        sql: String,
        params: Vec<String>,
    ) -> Result<wit_database::QueryResult, wit_database::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result: Result<wit_database::QueryResult, wit_database::Error> = async move {
            // Clear previous error detail on each call.
            self.last_db_error.clear();

            // MCP-788 (2026-05-14): pure-validation surfaces (capability
            // gate, SQL size cap, params size cap) MUST run BEFORE
            // `check_rate_limit` charges `db_query_count`. Pre-fix the
            // rate-limit charge ran FIRST, before even the capability
            // gate (defense-in-depth check ordered after the charge —
            // worse than the http/email/graphql sweep where capability
            // was already at the top). A Database-world guest could
            // drain MAX_DB_QUERIES_PER_EXECUTION (500/exec) by submitting
            // 64 KiB+1-byte SQL queries that fail the size cap, with
            // zero queries reaching sqlparser or the controller. The
            // capability-gate variant of the drain is theoretical
            // (WIT linkage already rejects non-Database imports at
            // module load) but defense-in-depth ordering still belongs
            // at the top. Rate-limit + sqlparser order is preserved
            // (charge BEFORE sqlparser since sqlparser consumes CPU and
            // is a legitimate resource cost that should count against
            // the per-execution budget). Same shape as MCP-770/783/784/
            // 785/786/787 and MCP-612 (counter-only-advances-when-
            // admitted).
            use crate::wit_inspector::CapabilityWorld;
            if !matches!(
                self.capability_world,
                CapabilityWorld::Database | CapabilityWorld::Trusted
            ) {
                self.record_capability_denied("database-query", "capability-world", "")
                    .await;
                tracing::warn!(
                    "WASM module attempted database access but lacks Database capability"
                );
                self.last_db_error =
                "Module lacks Database capability — compile with database-node or trusted world"
                    .to_string();
                return Err(wit_database::Error::Connectionfailed);
            }
            // MCP-755 (2026-05-13): cap SQL + aggregate params size BEFORE
            // sqlparser runs AND BEFORE the audit-ledger row is written.
            // Pre-fix `execute_query` accepted unbounded `sql: String` and
            // `params: Vec<String>` from the guest. Two real impacts:
            //
            //  * Audit-ledger poisoning. The WORM ledger at line ~5129
            //    appends the FULL SQL string (`"sql": sql`) on every
            //    successful validate. With MAX_DB_QUERIES_PER_EXECUTION =
            //    500, a Database-world guest could write 500 × 10 MiB =
            //    5 GiB to the local WORM ledger PLUS NATS-publish 5 GiB
            //    of audit events per execution. Both surfaces are shared
            //    across tenants — one noisy guest drowns out the audit
            //    signal for everyone else.
            //
            //  * sqlparser DoS. `Parser::parse_sql` on a 10 MiB input
            //    consumes proportional CPU + memory and runs on the
            //    worker's tokio task (`async fn` but the parse itself is
            //    sync); fuel-bounded guests can still pin the host
            //    thread for the duration of the parse.
            //
            // 64 KiB SQL cap is well above any reasonable hand-written or
            // ORM-generated query (Postgres' own libpq default
            // `statement_size_limit` is 1 GiB but real-world queries
            // rarely exceed a few KiB). 1 MiB aggregate params cap covers
            // any plausible bind set (1024 × 1 KiB params or 1 × 1 MiB
            // BYTEA-ish text payload). Same sibling-defense rule as
            // MCP-754: when one method in an impl block enforces a
            // bound, audit every other method for the same bound — even
            // when the cap was never previously written down.
            const MAX_SQL_BYTES: usize = 64 * 1024;
            const MAX_DB_PARAMS_BYTES: usize = 1024 * 1024;
            if sql.len() > MAX_SQL_BYTES {
                tracing::warn!(
                    module_id = ?self.module_id,
                    sql_len = sql.len(),
                    "wit_database: SQL exceeds {} bytes; rejecting",
                    MAX_SQL_BYTES
                );
                self.last_db_error = format!(
                    "SQL query exceeds {} bytes — split into smaller queries or pre-aggregate via bind params",
                    MAX_SQL_BYTES
                );
                return Err(wit_database::Error::Invalidquery);
            }
            let params_total: usize = params.iter().map(|p| p.len()).sum();
            if params_total > MAX_DB_PARAMS_BYTES {
                tracing::warn!(
                    module_id = ?self.module_id,
                    params_count = params.len(),
                    params_bytes = params_total,
                    "wit_database: aggregate params exceed {} bytes; rejecting",
                    MAX_DB_PARAMS_BYTES
                );
                self.last_db_error = format!(
                    "Bind parameters exceed {} bytes total — split the call or stream the payload via filesystem",
                    MAX_DB_PARAMS_BYTES
                );
                return Err(wit_database::Error::Invalidquery);
            }

            // Rate limit + cancellation: now charged AFTER capability and
            // pure-validation size caps — see MCP-788 reorder comment at
            // top of this function. Charged BEFORE sqlparser since the
            // parser is a legitimate CPU cost that should count against
            // the per-execution budget.
            if !self.check_rate_limit(&self.db_query_count, MAX_DB_QUERIES_PER_EXECUTION) {
                tracing::warn!(module_id = ?self.module_id, "Database query rate limit exceeded");
                if let Some(ref m) = self.metrics {
                    m.record_rate_limit_exceeded("db");
                }
                self.last_db_error =
                    "Rate limit exceeded: too many database queries in this execution".to_string();
                return Err(wit_database::Error::Unauthorized);
            }
            if self.is_cancelled() {
                tracing::info!(module_id = ?self.module_id, "Execution cancelled");
                if let Some(ref m) = self.metrics {
                    m.record_execution_cancelled();
                }
                self.last_db_error = "Execution was cancelled".to_string();
                return Err(wit_database::Error::Unauthorized);
            }

            // ── SQL operation policy enforcement (AST-based) ─────────────────
            // Validation stays worker-side so bad SQL is rejected without
            // a network hop. The controller re-verifies the HMAC on the
            // RPC and runs the actual query.
            // MCP-578: validate_sql now returns ValidatedStmt with
            // AST-derived `returns_rows`. We use that for is_fetch
            // routing below instead of the historical substring
            // `.contains("RETURNING")` heuristic which false-positived
            // on string literals and identifier substrings — a
            // false-positive caused the controller to CTE-wrap a
            // non-returning DML, which Postgres rejects, and the
            // operator's INSERT/UPDATE/DELETE never ran.
            let validated =
                match crate::sql_validator::validate_sql(&sql, &self.allowed_sql_operations) {
                    Ok(t) => t,
                    Err(e) => {
                        // Audit the denied SQL operation. The audit `target`
                        // is the validator's reason (the SQL operation kind
                        // — INSERT/DELETE/etc., or "syntax-error"); the SQL
                        // text itself is NOT audited because guest-supplied
                        // SQL can carry user-controlled string literals that
                        // shouldn't end up in the WORM ledger.
                        let reason = e.to_string();
                        let target = reason.split(':').next().unwrap_or("invalid").trim();
                        self.record_capability_denied("database-query", "sql-allowlist", target)
                            .await;
                        // MCP-538: byte-slice fixed-offset truncation
                        // panics on a multi-byte codepoint boundary.
                        // Pre-fix `&sql[..sql.len().min(200)]` would
                        // panic if the SQL contained a multi-byte UTF-8
                        // char (e.g. `é`, `你`) straddling byte 200 —
                        // achievable via a `WHERE name = '…'` literal.
                        // Use the same `floor_char_boundary` pattern as
                        // `runtime.rs::PASSING TO WASM NODE` so the
                        // worker crate stays consistent. Same class
                        // as MCP-477/478/479 — see
                        // `memory/byte_slice_utf8_panic_pattern.md`.
                        let preview_end = sql.len().min(200);
                        let safe_end = sql.floor_char_boundary(preview_end);
                        tracing::warn!(
                            error = %e,
                            sql_preview = %&sql[..safe_end],
                            "SQL validation rejected query"
                        );
                        self.last_db_error = e.to_string();
                        return Err(wit_database::Error::Invalidquery);
                    }
                };

            if let Some(ledger_mutex) = &self.audit_ledger {
                // Wasm-security review 2026-05-23 (M): stop logging the
                // FULL params array verbatim. Bind parameters often
                // carry PII (`SET password_hash = $1`, `WHERE email = $1`)
                // or short-lived secrets (`SET api_key = $1`). Pre-fix
                // the WORM ledger + NATS audit stream stored the raw
                // values, and at 1 MiB aggregate × 500 queries/exec the
                // worst-case audit dump was ~500 MiB per execution.
                // Replace the literal `params` with:
                //   - `params_count`     — operator-actionable cardinality
                //   - `params_bytes`     — aggregate size for capacity planning
                //   - `params_hash`      — sha256 over the canonical
                //                          (length-prefixed) params blob
                //                          so two identical-input audits
                //                          are linkable without exposure
                // The SQL string stays — it's bounded to 64 KiB upstream
                // by the size cap and ALWAYS reaches the controller
                // anyway (for replay), so retaining it adds no marginal
                // exposure.
                use sha2::Digest;
                let mut params_hasher = sha2::Sha256::new();
                let mut params_bytes: usize = 0;
                for p in &params {
                    params_hasher.update((p.len() as u64).to_le_bytes());
                    params_hasher.update(p.as_bytes());
                    params_bytes = params_bytes.saturating_add(p.len());
                }
                let params_hash = hex::encode(params_hasher.finalize());
                let mut ledger = ledger_mutex.lock().await;
                let event = ledger.append(
                    "agent:wasm",
                    "wasi:database_execute_query",
                    &serde_json::json!({
                        "sql": sql,
                        "params_count": params.len(),
                        "params_bytes": params_bytes,
                        "params_hash": params_hash,
                    })
                    .to_string(),
                );
                if let Some(n) = &self.nats_client {
                    let payload = serde_json::json!({
                        "event": event.clone(),
                        "hash": event.calculate_hash()
                    });
                    // MCP-879 (2026-05-14): log NATS publish failure
                    // explicitly so SIEM operators see the replication
                    // gap. Local ledger.append above is the WORM
                    // source-of-truth; this publish is replication
                    // only. Sibling to the MCP-735 fix at line ~2624
                    // (secrets_get) which already added this shape.
                    if let Err(e) = n
                        .publish(
                            "talos.audit.ledger".to_string(),
                            serde_json::to_vec(&payload).unwrap_or_default().into(),
                        )
                        .await
                    {
                        tracing::warn!(
                            target: "talos_rpc",
                            error = %e,
                            "audit-ledger NATS replication failed (database_query) — local ledger unaffected, SIEM stream will miss this event"
                        );
                    }
                }
            }

            // Actor context + NATS are required for dispatch. Anonymous
            // sandboxes (no actor_id) cannot issue database queries.
            let Some(actor_id) = self.actor_id else {
                self.last_db_error =
                    "Anonymous execution — database queries require an actor_id".to_string();
                return Err(wit_database::Error::Unauthorized);
            };
            let Some(nats) = self.nats_client.as_ref().cloned() else {
                self.last_db_error =
                    "NATS client unavailable — cannot dispatch database RPC".to_string();
                return Err(wit_database::Error::Connectionfailed);
            };

            // Detect fetch vs execute once and send the flag over the
            // wire so the controller doesn't re-parse. MCP-578: derive
            // from the parsed AST (validate_sql -> ValidatedStmt) rather
            // than a substring sniff on the raw SQL. The substring path
            // had two false-positive classes: string-literal "RETURNING"
            // (`INSERT INTO logs (msg) VALUES ('returning home')`) and
            // identifier substrings (`UPDATE u SET returning_user = 1`).
            // Both caused the controller to CTE-wrap the DML, which
            // Postgres rejects with "WITH query has no RETURNING
            // clause" — the operator's mutation never ran.
            let is_fetch = validated.returns_rows;
            let _ = &validated.stmt_type; // retained for forward-compat / future routing

            let rpc_req = match talos_memory::database_rpc::DatabaseRpcRequest::new_signed(
                actor_id,
                sql.clone(),
                params.clone(),
                is_fetch,
            ) {
                Some(r) => r,
                None => {
                    self.last_db_error =
                        "HMAC key unavailable on worker — refusing to send unsigned DB request"
                            .to_string();
                    return Err(wit_database::Error::Unauthorized);
                }
            };
            let payload = match serde_json::to_vec(&rpc_req) {
                Ok(p) => p,
                Err(e) => {
                    self.last_db_error = format!("serialize DB RPC: {e}");
                    return Err(wit_database::Error::Queryerror);
                }
            };

            use talos_memory::database_rpc::{
                DatabaseRpcError, DatabaseRpcReply, REQUEST_TIMEOUT_MS, SUBJECT_DATABASE_QUERY,
            };
            let reply_msg = match tokio::time::timeout(
                std::time::Duration::from_millis(REQUEST_TIMEOUT_MS),
                nats.request(SUBJECT_DATABASE_QUERY, payload.into()),
            )
            .await
            {
                Ok(Ok(m)) => m,
                Ok(Err(e)) => {
                    self.last_db_error = format!("NATS request failed: {e}");
                    return Err(wit_database::Error::Connectionfailed);
                }
                Err(_) => {
                    self.last_db_error = "Database RPC timed out".to_string();
                    return Err(wit_database::Error::Queryerror);
                }
            };

            let reply: DatabaseRpcReply = match serde_json::from_slice(&reply_msg.payload) {
                Ok(r) => r,
                Err(e) => {
                    self.last_db_error = format!("DB RPC reply decode: {e}");
                    return Err(wit_database::Error::Queryerror);
                }
            };

            match reply.result {
                Ok(rows) => Ok(wit_database::QueryResult {
                    rows: rows.rows_json,
                    rows_affected: rows.rows_affected,
                }),
                Err(DatabaseRpcError::Unauthorized) => {
                    self.last_db_error = "Controller rejected request (HMAC mismatch)".to_string();
                    Err(wit_database::Error::Unauthorized)
                }
                Err(DatabaseRpcError::InvalidQuery(m)) => {
                    self.last_db_error = m;
                    Err(wit_database::Error::Invalidquery)
                }
                Err(DatabaseRpcError::ConnectionFailed(m)) => {
                    self.last_db_error = m;
                    Err(wit_database::Error::Connectionfailed)
                }
                Err(DatabaseRpcError::ResultTooLarge(m)) => {
                    self.last_db_error = m;
                    Err(wit_database::Error::Queryerror)
                }
                Err(DatabaseRpcError::Timeout) => {
                    self.last_db_error = "Database query timed out on controller".to_string();
                    Err(wit_database::Error::Queryerror)
                }
                Err(DatabaseRpcError::QueryError(m)) => {
                    self.last_db_error = m;
                    Err(wit_database::Error::Queryerror)
                }
            }
        }
        .await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call("db::execute_query", __start.elapsed().as_millis() as f64);
        }
        __result
    }

    async fn get_last_error(&mut self) -> String {
        self.last_db_error.clone()
    }
}
