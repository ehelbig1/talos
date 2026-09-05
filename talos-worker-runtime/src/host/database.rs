//! `database` host interface (signed NATS-RPC to the controller;
//! SQL validation via `sql_validator`).

use super::*;

/// Does this statement need the write ceiling consulted, and under what audit
/// label?
///
/// The whole of the ceiling decision for `database-query`, in one pure
/// function with ONE caller (`execute_query`, below), so that the expression
/// the tests drive IS the expression the host function evaluates.
///
/// That is not incidental. The first version of the tests for this fix drove a
/// helper that re-derived `!validated.access.is_read_only()` rather than
/// calling the gate, and a mutation reverting the CALL SITE to the old
/// `matches!(validated.stmt_type, "SELECT" | "EXPLAIN")` string match passed
/// all 635 crate tests — the same shape as `guard_that_passes_its_own_mutation`
/// in the project's own notes. Naming the decision is what makes the mutation
/// visible; lint check 85(d) is the second copy, because a test can be
/// bypassed by inlining a different expression at the call site and a grep for
/// that expression cannot.
///
/// The verdict comes from [`talos_sql_classify`] — the one implementation of
/// "does this SQL mutate?" in the workspace, shared with the controller's
/// `talos.database.query` handler — applied to the AST the validator already
/// parsed. It is deliberately NOT derived from `stmt_type`, which is a
/// top-level LABEL: `WITH ins AS (INSERT … RETURNING a) SELECT * FROM ins`
/// is labelled `"SELECT"` because its root really is a `Statement::Query`.
///
/// Fail-closed: DDL, `CALL`, and any sqlparser variant the classifier has not
/// been taught are `SqlAccess::Unclassified`, which is not a read.
///
/// It returns the audit LABEL rather than a bool so the call site has no
/// boolean to invert and nowhere to inline a competing predicate — the seam a
/// mutation used. It also ties the label to the decision: the string handed to
/// `write_ceiling_refuses` now comes from the same call that decided to refuse,
/// instead of being fetched separately from a field that means something else.
/// The label is the statement TYPE, matching what the controller stamps: guest
/// SQL carries literals and literals carry PII.
#[must_use]
pub(crate) fn write_ceiling_audit_target(
    validated: &crate::sql_validator::ValidatedStmt,
) -> Option<&str> {
    if validated.access.is_read_only() {
        None
    } else {
        Some(validated.stmt_type.as_str())
    }
}

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

            // Write-ceiling gate: a read-only actor may run a read but never
            // a mutation. The decision comes from `talos_sql_classify` — the
            // ONE implementation of "does this mutate?", shared with the
            // controller's `talos.database.query` handler — applied to the AST
            // the validator just parsed.
            //
            // It used to be `matches!(validated.stmt_type, "SELECT" |
            // "EXPLAIN")`, a match on the top-level statement LABEL. That
            // labels `WITH ins AS (INSERT INTO t VALUES (1) RETURNING a)
            // SELECT * FROM ins` as `"SELECT"`, because its root really is a
            // `Statement::Query`, so a `readonly` actor's INSERT was forwarded
            // to the controller as a read. The controller's own gate (#757)
            // caught it there; the worker — the documented PRIMARY fence —
            // did not, and the two sides disagreed about the same statement.
            //
            // Fail-closed is unchanged and now stronger: DDL, `CALL`, and any
            // sqlparser variant the classifier has not been taught land in
            // `SqlAccess::Unclassified`, which is not a read. (`EXPLAIN` moves
            // from read to non-read, which changes NO live decision: the
            // validator's `always_blocked_label` refuses every EXPLAIN
            // unconditionally several lines above, so the old `"EXPLAIN"` arm
            // was unreachable — pinned by `explain_never_reaches_the_ceiling_gate`.)
            //
            // The gate is an `if let` over `write_ceiling_audit_target`, not a
            // boolean: see that function for why the call site deliberately
            // has no invertible condition of its own.
            if let Some(audit_target) = write_ceiling_audit_target(&validated) {
                if self
                    .write_ceiling_refuses("database-query", audit_target)
                    .await
                {
                    self.last_db_error =
                        "write ceiling: this read-only actor cannot run a mutating query"
                            .to_string();
                    return Err(wit_database::Error::Unauthorized);
                }
            }

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
                            talos_workflow_job_protocol::subjects::AUDIT_LEDGER.to_string(),
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
                // #754: the controller enforces the same write ceiling this
                // host fn enforces above, because the fleet-shared signature
                // proves possession of a key, not that any gate ran. Reaching
                // this arm means THIS worker did not refuse — its
                // `TALOS_WRITE_CEILING_ENFORCED` is unset while the
                // controller's is set. Mapped to the SAME guest-visible error
                // the local gate returns, so a module cannot tell which
                // process refused it (and does not need to).
                Err(DatabaseRpcError::WriteCeiling) => {
                    self.last_db_error =
                        "write ceiling: this read-only actor cannot run a mutating query"
                            .to_string();
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

#[cfg(test)]
mod write_ceiling_db_tests {
    use crate::sql_validator::{validate_sql_with_policy, EmptyAllowlistPolicy};
    use talos_sql_classify::SqlAccess;

    /// What the ceiling gate in `execute_query` decides, driven through the
    /// REAL path: the validator parses and classifies, and the gate reads
    /// `validated.access.is_read_only()`. Nothing here re-derives the verdict.
    #[derive(Debug, PartialEq, Eq)]
    enum Decision {
        /// The validator refused before the ceiling was consulted.
        ValidatorRefused,
        /// Admitted as a read — a `readonly` actor may run it.
        PermittedAsRead,
        /// Classified as a mutation — the ceiling gate fires.
        CeilingGateFires,
    }

    /// Drives the REAL path end to end: the validator parses and classifies,
    /// then `super::write_ceiling_audit_target` — the exact expression
    /// `execute_query` evaluates, not a copy of it — decides. Nothing here
    /// re-derives the verdict; that mistake is documented on
    /// `write_ceiling_applies` itself.
    fn decide(sql: &str, ops: &[String], empty_policy: EmptyAllowlistPolicy) -> Decision {
        match validate_sql_with_policy(sql, ops, empty_policy) {
            Err(_) => Decision::ValidatorRefused,
            Ok(v) if super::write_ceiling_audit_target(&v).is_some() => Decision::CeilingGateFires,
            Ok(_) => Decision::PermittedAsRead,
        }
    }

    fn ops(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    /// # The hole this test exists for
    ///
    /// Postgres data-modifying CTEs parse as `Statement::Query`, so the
    /// pre-fix gate — `matches!(validated.stmt_type, "SELECT" | "EXPLAIN")` —
    /// called them reads and forwarded a `readonly` actor's INSERT to the
    /// controller. Run against the pre-fix tree these two cases assert
    /// `CeilingGateFires` and get `PermittedAsRead`.
    ///
    /// The allowlist here ADMITS the mutation on purpose: the module's
    /// `allowed_operations` policy and the actor's write ceiling are different
    /// controls, and this test is about the ceiling. `DELETE` and `MERGE`
    /// inside a CTE are sqlparser 0.53 parse errors and are pinned as such by
    /// `talos_sql_classify`.
    #[test]
    fn a_writable_cte_reaches_the_ceiling_gate() {
        let allowed = ops(&["INSERT", "UPDATE", "DELETE"]);
        for sql in [
            "WITH ins AS (INSERT INTO t (a) VALUES (1) RETURNING a) SELECT * FROM ins",
            "WITH d AS (UPDATE t SET a = 1 RETURNING a) SELECT * FROM d",
            "WITH a AS (SELECT 1), b AS (INSERT INTO t VALUES (1) RETURNING 1) SELECT * FROM a",
            "SELECT * FROM (WITH x AS (INSERT INTO t VALUES (1) RETURNING 1) SELECT * FROM x) y",
        ] {
            assert_eq!(
                decide(sql, &allowed, EmptyAllowlistPolicy::AllowAllNonDdl),
                Decision::CeilingGateFires,
                "a mutation hidden in a CTE must not be admitted as a read: {sql}"
            );
        }
    }

    /// Controls. A plain read is still a read and a plain mutation is still a
    /// mutation — the fix must change no existing decision.
    #[test]
    fn plain_statements_decide_exactly_as_before() {
        let allowed = ops(&["INSERT", "UPDATE", "DELETE"]);
        for sql in [
            "SELECT 1",
            "SELECT * FROM users WHERE id = $1",
            "WITH a AS (SELECT 1) SELECT * FROM a",
            "SELECT * FROM t UNION SELECT * FROM u",
        ] {
            assert_eq!(
                decide(sql, &allowed, EmptyAllowlistPolicy::DenyMutations),
                Decision::PermittedAsRead,
                "control read: {sql}"
            );
        }
        for sql in [
            "INSERT INTO t (a) VALUES ($1)",
            "UPDATE t SET a = 1 WHERE id = $1",
            "DELETE FROM t WHERE id = $1",
        ] {
            assert_eq!(
                decide(sql, &allowed, EmptyAllowlistPolicy::AllowAllNonDdl),
                Decision::CeilingGateFires,
                "control mutation: {sql}"
            );
        }
    }

    /// # The module-policy half, which is a different control and was also open
    ///
    /// `enforce_cte_mutation_policy` used to skip its allowlist test entirely
    /// when `allowed_operations` was empty, so a writable CTE validated clean
    /// under `DenyMutations` — the production default, whose documented
    /// contract is "only SELECT passes when the allowlist is empty", and the
    /// ONLY configuration that exists (every dispatch site hardcodes
    /// `allowed_sql_operations: vec![]`). Pre-fix this asserts
    /// `ValidatorRefused` and gets `PermittedAsRead`.
    #[test]
    fn an_empty_allowlist_refuses_a_writable_cte_like_it_refuses_a_bare_insert() {
        for sql in [
            "WITH ins AS (INSERT INTO t (a) VALUES (1) RETURNING a) SELECT * FROM ins",
            "WITH d AS (UPDATE t SET a = 1 RETURNING a) SELECT * FROM d",
            "SELECT * FROM (WITH x AS (INSERT INTO t VALUES (1) RETURNING 1) SELECT * FROM x) y",
            // The statement the empty-allowlist contract is written about,
            // as the control that it already behaved correctly.
            "INSERT INTO t (a) VALUES (1)",
        ] {
            assert_eq!(
                decide(sql, &[], EmptyAllowlistPolicy::DenyMutations),
                Decision::ValidatorRefused,
                "empty allowlist under DenyMutations must refuse: {sql}"
            );
        }
        // A read is untouched by the fix.
        assert_eq!(
            decide("SELECT * FROM t", &[], EmptyAllowlistPolicy::DenyMutations),
            Decision::PermittedAsRead
        );
    }

    /// Legacy permissive mode gives the SAME answer to the same question in
    /// both positions: it admits a top-level mutation, so it admits one inside
    /// a CTE — and the ceiling gate, not the allowlist, is what stops a
    /// `readonly` actor there.
    #[test]
    fn permissive_empty_allowlist_treats_cte_and_top_level_alike() {
        for sql in [
            "WITH ins AS (INSERT INTO t (a) VALUES (1) RETURNING a) SELECT * FROM ins",
            "INSERT INTO t (a) VALUES (1)",
        ] {
            assert_eq!(
                decide(sql, &[], EmptyAllowlistPolicy::AllowAllNonDdl),
                Decision::CeilingGateFires,
                "{sql}"
            );
        }
    }

    /// Reclassifying `EXPLAIN` from read to non-read changes no live decision,
    /// because the validator refuses every EXPLAIN before the gate is reached.
    /// Recorded so the claim is checked rather than asserted.
    #[test]
    fn explain_never_reaches_the_ceiling_gate() {
        for sql in [
            "EXPLAIN SELECT 1",
            "EXPLAIN ANALYZE INSERT INTO t VALUES (1)",
        ] {
            assert_eq!(
                decide(sql, &ops(&["INSERT"]), EmptyAllowlistPolicy::AllowAllNonDdl),
                Decision::ValidatorRefused,
                "{sql}"
            );
        }
    }

    /// DDL / `CALL` / `COPY` / `SET` are refused by the validator, and would
    /// fail closed at the gate even if they were not: they classify as
    /// `Unclassified`, which is not a read.
    #[test]
    fn non_data_statements_fail_closed_at_both_layers() {
        for sql in [
            "CREATE TABLE t (id INT)",
            "DROP TABLE t",
            "TRUNCATE t",
            "GRANT SELECT ON t TO r",
            "COPY t FROM '/etc/passwd'",
            "SET search_path = x",
        ] {
            assert_eq!(
                decide(sql, &[], EmptyAllowlistPolicy::AllowAllNonDdl),
                Decision::ValidatorRefused,
                "{sql}"
            );
            let stmt = sqlparser::parser::Parser::parse_sql(
                &sqlparser::dialect::PostgreSqlDialect {},
                sql,
            )
            .expect("parses");
            assert_eq!(
                talos_sql_classify::classify(&stmt[0]),
                SqlAccess::Unclassified,
                "backstop: {sql}"
            );
        }
    }
}
