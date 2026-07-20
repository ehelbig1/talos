//! Execution aggregate: creation + concurrency/budget admission,
//! status transitions, output persistence, and failure alerts.
//!
//! NOTE (known domain leakage, follow-up from the crate review):
//! output-at-rest encryption routes through `talos-secrets-manager`
//! (`maybe_encrypt_execution_output` / the decrypt branch of
//! `list_recent_completed_outputs`). Kept verbatim in this split.

use crate::*;

/// Outcome of [`WorkflowRepository::create_execution_under_concurrency_limit`].
///
/// Carrying the limit and the observed running count in
/// `LimitReached` lets the caller render an actionable message
/// without re-querying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcurrencyAdmission {
    /// Execution row was created. Caller proceeds with dispatch.
    Created,
    /// `max_concurrent_executions` would be exceeded. No row was
    /// written. `limit` is the workflow's configured ceiling;
    /// `running` is the count observed inside the transaction
    /// (always `>= limit`).
    LimitReached { limit: i32, running: i64 },
    /// The triggering actor's budget would be exceeded. No row was
    /// written. `kind` is `"per_minute"` / `"per_hour"` / `"total"`
    /// (execution-count caps) or `"fuel_per_hour"` (rolling fuel sum);
    /// `limit` is the configured cap; `count` is the value observed
    /// inside the transaction (always `>= limit`) — an execution count
    /// for the count caps, a summed fuel total for `fuel_per_hour`.
    /// `limit` is `i64` so it can carry fuel caps that exceed `i32`.
    ///
    /// This is the ATOMIC backstop for the actor-budget gate: the
    /// fast-fail pre-check in `authorize_workflow_trigger` is lock-free
    /// check-then-act, so under concurrent triggers every request could
    /// read `count < cap` before any INSERT committed and blow past the
    /// cap (observed: a `max_executions_per_hour=2` actor admitted 10
    /// under a 20-way barrier-synchronised fire). The re-check below runs
    /// inside the row-creation transaction under a per-actor advisory
    /// lock, so it's atomic with the INSERT.
    ActorBudgetExceeded {
        kind: &'static str,
        limit: i64,
        count: i64,
    },
}

/// Render the human-facing message for a
/// [`ConcurrencyAdmission::ActorBudgetExceeded`] outcome. Centralised so the
/// four trigger paths (orchestration, GraphQL, MCP trigger/bulk/as-actors)
/// share one wording — and so the fuel cap (count = fuel units, not
/// executions) doesn't get the execution-count phrasing.
pub fn actor_budget_exceeded_message(kind: &str, limit: i64, count: i64) -> String {
    match kind {
        "fuel_per_hour" => format!(
            "Actor fuel budget exceeded: {count} fuel consumed in the last hour (limit: {limit})"
        ),
        "per_minute" => {
            format!("Actor budget exceeded: {count} executions in the last minute (limit: {limit})")
        }
        "per_hour" => {
            format!("Actor budget exceeded: {count} executions in the last hour (limit: {limit})")
        }
        _ => format!("Actor budget exceeded: {count} executions total (limit: {limit})"),
    }
}

/// Derive a stable per-actor key for `pg_advisory_xact_lock(bigint)` from
/// the actor UUID. Transaction-scoped advisory locks serialise execution
/// creation for the same actor so the in-transaction budget re-check in
/// [`WorkflowRepository::create_execution_under_concurrency_limit`] is
/// atomic with the INSERT (closes the actor-budget TOCTOU). A 64-bit
/// collision would merely serialise two unrelated actors together
/// occasionally — correctness-safe, perf-only.
pub(crate) fn actor_advisory_lock_key(actor_id: Uuid) -> i64 {
    let b = actor_id.as_bytes();
    i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Outcome of [`WorkflowRepository::create_executions_batch_under_concurrency_limit`].
///
/// Reports the prefix of input rows actually admitted plus the
/// observed cap parameters so the caller can render an actionable
/// "X of N admitted, Y throttled" response without re-querying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchAdmission {
    /// Number of rows inserted. The first `inserted` ids in the
    /// caller's `exec_ids` slice are now `'queued'`. Suffix was
    /// rejected.
    pub inserted: usize,
    /// `max_concurrent_executions` from the workflow row, if set.
    /// `None` means no cap was configured and every input was
    /// admitted.
    pub limit: Option<i32>,
    /// In-flight count observed inside the transaction
    /// (running + queued + pending). 0 when no cap is configured.
    pub running: i64,
}

/// Pure helper extracted for unit-testing the cap math without a
/// Postgres dependency. Used by
/// `create_executions_batch_under_concurrency_limit`.
pub(crate) fn compute_batch_admit_count(
    max_concurrent: Option<i32>,
    running: i64,
    requested: usize,
) -> usize {
    match max_concurrent {
        None => requested,
        Some(limit) => {
            let limit_i64 = i64::from(limit);
            let headroom = (limit_i64 - running).max(0) as usize;
            headroom.min(requested)
        }
    }
}

#[cfg(test)]
mod actor_lock_key_tests {
    use super::actor_advisory_lock_key;
    use uuid::Uuid;

    #[test]
    fn key_is_deterministic_and_distinct() {
        let a = Uuid::parse_str("d8aaa59a-bab7-4a7e-9c21-8ba041543403").unwrap();
        let b = Uuid::parse_str("cd4ac0f1-9a4b-425b-9434-c0dda50e0049").unwrap();
        // Same UUID → same key (serialises the same actor across calls).
        assert_eq!(actor_advisory_lock_key(a), actor_advisory_lock_key(a));
        // Different UUIDs → different keys (no spurious cross-actor serialisation).
        assert_ne!(actor_advisory_lock_key(a), actor_advisory_lock_key(b));
    }

    #[test]
    fn nil_uuid_maps_to_zero() {
        assert_eq!(actor_advisory_lock_key(Uuid::nil()), 0);
    }

    #[test]
    fn budget_message_distinguishes_fuel_from_counts() {
        use super::actor_budget_exceeded_message;
        // Fuel cap: count is fuel units, not executions, and the limit can be
        // large (i64) — must not say "executions".
        let m = actor_budget_exceeded_message("fuel_per_hour", 5_000_000_000, 6_000_000_000);
        assert!(m.contains("fuel"), "got: {m}");
        assert!(!m.contains("executions"), "got: {m}");
        assert!(
            m.contains("6000000000") && m.contains("5000000000"),
            "got: {m}"
        );
        // Count caps: distinct windows, phrased as executions.
        assert!(actor_budget_exceeded_message("per_minute", 10, 11).contains("in the last minute"));
        assert!(actor_budget_exceeded_message("per_hour", 10, 11).contains("in the last hour"));
        assert!(actor_budget_exceeded_message("total", 10, 11).contains("total"));
        assert!(actor_budget_exceeded_message("per_hour", 10, 11).contains("executions"));
    }
}

#[cfg(test)]
mod batch_admission_tests {
    use super::compute_batch_admit_count;

    #[test]
    fn no_cap_admits_full_batch() {
        assert_eq!(compute_batch_admit_count(None, 0, 100), 100);
        assert_eq!(compute_batch_admit_count(None, 9999, 1), 1);
    }

    #[test]
    fn full_headroom_admits_full_batch() {
        // cap 10, 0 running → all 5 inputs admitted.
        assert_eq!(compute_batch_admit_count(Some(10), 0, 5), 5);
    }

    #[test]
    fn partial_headroom_admits_prefix_only() {
        // cap 10, 7 running → 3 headroom; batch of 5 admits 3.
        assert_eq!(compute_batch_admit_count(Some(10), 7, 5), 3);
    }

    #[test]
    fn at_cap_admits_zero() {
        // cap 5, 5 running → 0 headroom.
        assert_eq!(compute_batch_admit_count(Some(5), 5, 100), 0);
    }

    #[test]
    fn over_cap_admits_zero() {
        // cap 5, 50 running (operator lowered the cap mid-flight) → 0.
        assert_eq!(compute_batch_admit_count(Some(5), 50, 100), 0);
    }

    #[test]
    fn exact_cap_match_admits_exact() {
        // cap 100, 0 running, batch of 100 → 100 (no throttle).
        assert_eq!(compute_batch_admit_count(Some(100), 0, 100), 100);
    }

    #[test]
    fn cap_larger_than_batch_admits_full() {
        // cap 1000, 5 running, batch of 10 → 10 (cap doesn't bite).
        assert_eq!(compute_batch_admit_count(Some(1000), 5, 10), 10);
    }

    #[test]
    fn empty_batch_admits_nothing() {
        assert_eq!(compute_batch_admit_count(None, 0, 0), 0);
        assert_eq!(compute_batch_admit_count(Some(10), 0, 0), 0);
    }
}

/// Initial status to stamp on a freshly-inserted `workflow_executions`
/// row. The MCP path dispatches synchronously and writes
/// [`Self::Running`]; the GraphQL path defers dispatch to a
/// `tokio::spawn` and writes [`Self::Queued`] so observers don't see
/// the row in `'running'` state before the engine has actually
/// received the JobRequest.
///
/// Defaults to [`Self::Running`] in the canonical entry-point so
/// existing MCP callers don't change behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InitialExecutionStatus {
    /// Synchronous dispatch — caller will fire the JobRequest before
    /// returning to the user. The default for MCP `trigger_workflow`
    /// and friends.
    #[default]
    Running,
    /// Deferred dispatch — caller spawns a background task that fires
    /// the JobRequest later. Used by the GraphQL `trigger_workflow`
    /// resolver, which spawns the dispatch path so the mutation
    /// returns to the client immediately.
    Queued,
}

impl InitialExecutionStatus {
    /// Render to the wire-format string accepted by the
    /// `workflow_executions.status` CHECK constraint. `'pending'` was
    /// removed by migration `20260314001000`; only `'running'` and
    /// `'queued'` are valid initial states today.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Queued => "queued",
        }
    }
}

#[cfg(test)]
mod initial_execution_status_tests {
    use super::*;

    #[test]
    fn default_is_running() {
        assert_eq!(
            InitialExecutionStatus::default(),
            InitialExecutionStatus::Running
        );
    }

    #[test]
    fn db_str_matches_check_constraint_values() {
        // The `workflow_executions.status` CHECK constraint accepts
        // 'running' and 'queued' (plus terminal states). Migration
        // `20260314001000` removed 'pending'. If the DB string drifts
        // from these literals, the canonical INSERT fails closed at
        // runtime with a constraint violation. Lock the wire form.
        assert_eq!(InitialExecutionStatus::Running.as_db_str(), "running");
        assert_eq!(InitialExecutionStatus::Queued.as_db_str(), "queued");
    }
}

#[cfg(test)]
mod execution_output_encryption_tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    /// Build a `WorkflowRepository` whose pool would panic if touched —
    /// for tests that only exercise the builder + state-checking
    /// helpers (no SQL). Mirrors the `SecretsManager::test_stub_for_cache`
    /// pattern used elsewhere in the workspace.
    fn lazy_repo() -> WorkflowRepository {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://stub:stub@127.0.0.1:1/stub")
            .expect("connect_lazy never errors at construction");
        WorkflowRepository::new(pool)
    }

    #[tokio::test]
    async fn maybe_encrypt_returns_none_without_secrets_manager() {
        // Without `with_encryption`, the helper short-circuits to
        // `Ok(None)` so `mark_execution_*` falls back to the plaintext
        // branch (which symmetrically NULLs the ciphertext columns).
        // This is the canonical test-environment shape — production
        // wires the SM via main.rs.
        let repo = lazy_repo();
        let payload = serde_json::json!({"k": "v"});
        let out = repo
            .maybe_encrypt_execution_output(Uuid::nil(), &payload)
            .await
            .expect("ok branch");
        assert!(out.is_none());
    }
}

#[derive(Debug)]
pub struct ActorRow {
    pub id: Uuid,
    pub name: String,
    pub status: String,
    pub max_workflow_count: Option<i32>,
    pub max_executions_per_hour: Option<i32>,
    pub max_executions_total: Option<i64>,
    /// True for the user's auto-provisioned default actor. The
    /// trigger-authorization gate enforces budget/status/tier against it but
    /// SKIPS the capability-ceiling check (it's an identity/budget bucket, not
    /// a capability sandbox — the module's compiled world is the real bound).
    pub is_default: bool,
}

impl WorkflowRepository {
    /// Helper used by the encrypted branch of `mark_execution_*`.
    /// Returns `Ok(None)` when no SecretsManager is wired (the caller
    /// then falls back to the plaintext branch). Centralised so the
    /// encrypt-or-plaintext decision lives in one place.
    ///
    /// MCP-S2: every caller binds AAD = exec_id so a swap of
    /// output_data_enc across rows is detected on read. Returns
    /// (key_id, ciphertext, format_version) so the caller can persist
    /// all three in lockstep — without the format column write, the
    /// read path would dispatch via v0 and fail to decrypt.
    async fn maybe_encrypt_execution_output(
        &self,
        exec_id: Uuid,
        output: &serde_json::Value,
    ) -> Result<Option<(Uuid, Vec<u8>, i16)>> {
        let Some(sm) = self.secrets_manager.as_ref() else {
            return Ok(None);
        };
        let json_str = serde_json::to_string(output)?;
        let (key_id, enc_bytes, version) = sm
            .encrypt_value_aad_v3(&json_str, exec_id.as_bytes())
            .await?;
        Ok(Some((key_id, enc_bytes, version)))
    }

    // ── Execution control ──────────────────────────────────────────────────

    /// Returns true if the global execution queue has been paused by an operator.
    /// Appears 5+ times in the original handlers — centralised here.
    pub async fn is_execution_paused(&self) -> Result<bool> {
        let paused: Option<bool> = sqlx::query_scalar(
            "SELECT (value)::text = 'true' FROM system_settings \
             WHERE key = 'execution_paused'",
        )
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(paused.unwrap_or(false))
    }

    /// Set the execution_paused system setting.
    pub async fn set_execution_paused(&self, paused: bool) -> Result<()> {
        let value = if paused { "true" } else { "false" };
        sqlx::query(
            "INSERT INTO system_settings (key, value) VALUES ('execution_paused', $1) \
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(value)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Count active (running/queued/pending) executions for a workflow.
    pub async fn count_running_executions(&self, workflow_id: Uuid) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM workflow_executions \
             WHERE workflow_id = $1 AND status IN ('running', 'queued', 'pending', 'resuming')",
        )
        .bind(workflow_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    /// Insert a new workflow execution record.
    ///
    /// Thin wrapper around [`Self::create_execution_with_lineage`]. The
    /// underlying SQL gates on `(workflow_id, user_id)` ownership match
    /// (T5-N3 / T7-N1); the wrapper bails with `anyhow::Error` when
    /// `rows_affected == 0` so existing callers that don't track row
    /// counts still observe the failure instead of silently no-op'ing.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_execution(
        &self,
        id: Uuid,
        workflow_id: Uuid,
        user_id: Uuid,
        version_id: Option<Uuid>,
        priority: Option<&str>,
        actor_id: Option<Uuid>,
        provenance: Option<&serde_json::Value>,
    ) -> Result<()> {
        let rows = self
            .create_execution_with_lineage(
                id,
                workflow_id,
                user_id,
                version_id,
                priority,
                actor_id,
                provenance,
                None,
                None,
            )
            .await?;
        if rows == 0 {
            anyhow::bail!(
                "create_execution: ownership mismatch — workflow_id {workflow_id} \
                 does not belong to user_id {user_id} (or workflow not found)"
            );
        }
        Ok(())
    }

    /// Atomically check the per-workflow concurrency limit and create a
    /// new execution row if there's headroom, in a single transaction.
    ///
    /// Pre-r296 the equivalent operation was two separate SQL calls
    /// (`count_running_executions` then `create_execution_with_lineage`)
    /// with a TOCTOU window between them: two concurrent triggers
    /// against a workflow at its limit could both pass the count check
    /// and then both INSERT, exceeding the cap. The transactional
    /// variant locks the `workflows` row with `SELECT … FOR UPDATE` so
    /// a second trigger waits until the first commits — at which point
    /// its COUNT sees the new row and the cap is enforced correctly.
    ///
    /// `max_concurrent_executions = NULL` means no limit; the workflow
    /// row is still locked for the duration of the transaction (cheap
    /// — held only for the COUNT + INSERT round trip), but the count
    /// check is skipped.
    ///
    /// Returns `ConcurrencyAdmission::Created` on success or
    /// `ConcurrencyAdmission::LimitReached` if the cap would be
    /// exceeded; the transaction is rolled back in the latter case so
    /// no row is written.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_execution_under_concurrency_limit(
        &self,
        id: Uuid,
        workflow_id: Uuid,
        user_id: Uuid,
        version_id: Option<Uuid>,
        priority: Option<&str>,
        actor_id: Option<Uuid>,
        provenance: Option<&serde_json::Value>,
        parent_execution_id: Option<Uuid>,
        root_execution_id: Option<Uuid>,
        initial_status: InitialExecutionStatus,
    ) -> Result<ConcurrencyAdmission> {
        let mut tx = self.db_pool.begin().await?;

        // Actor-budget atomic backstop (battle-hardening). The fast-fail
        // pre-check in `authorize_workflow_trigger` is lock-free
        // check-then-act, so concurrent triggers can all read
        // `count < cap` before any INSERT commits and exceed the actor's
        // `max_executions_per_hour` / `max_executions_total` cap. Take a
        // transaction-scoped advisory lock keyed on the actor FIRST (a
        // stable lock order — actor before the workflow row below — so no
        // deadlock vs. a no-actor trigger that only takes the row lock),
        // then re-evaluate the budget inside the same transaction so the
        // check is atomic with the INSERT. Serialises execution creation
        // per-actor across ALL workflows, which the workflow-row lock
        // alone can't (different workflows → different rows). The pre-check
        // stays as a fast-fail + owner of the `on_budget_exceeded=suspend`
        // side-effect; this is the pure hard-cap race-closer.
        if let Some(aid) = actor_id {
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(actor_advisory_lock_key(aid))
                .execute(&mut *tx)
                .await?;

            let policy: Option<(
                Option<i32>,
                Option<i32>,
                Option<i32>,
                Option<i64>,
                Option<i64>,
            )> = sqlx::query_as(
                "SELECT max_executions_per_hour, max_executions_total, \
                     max_workflows_per_minute, max_fuel_per_hour, max_llm_tokens_per_day \
                     FROM actor_budget_policies WHERE actor_id = $1",
            )
            .bind(aid)
            .fetch_optional(&mut *tx)
            .await?;

            if let Some((per_hour, total, per_minute, fuel_per_hour, llm_tokens_per_day)) = policy {
                // Per-minute trigger-rate cap. Counts only rows that carry
                // this actor_id — top-level triggers (bulk_trigger /
                // trigger_as_actors included). Sub-workflow chain rows are
                // inserted with actor_id = NULL and in-process sub-workflow
                // dispatch creates no execution rows, so neither inflates
                // this count. Same advisory-lock serialisation as the
                // per-hour / total caps above → atomic with the INSERT.
                if let Some(limit) = per_minute {
                    let count: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM workflow_executions \
                         WHERE actor_id = $1 AND started_at > now() - INTERVAL '1 minute'",
                    )
                    .bind(aid)
                    .fetch_one(&mut *tx)
                    .await?;
                    if count >= i64::from(limit) {
                        tx.rollback().await?;
                        return Ok(ConcurrencyAdmission::ActorBudgetExceeded {
                            kind: "per_minute",
                            limit: i64::from(limit),
                            count,
                        });
                    }
                }
                if let Some(limit) = per_hour {
                    let count: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM workflow_executions \
                         WHERE actor_id = $1 AND started_at > now() - INTERVAL '1 hour'",
                    )
                    .bind(aid)
                    .fetch_one(&mut *tx)
                    .await?;
                    if count >= i64::from(limit) {
                        tx.rollback().await?;
                        return Ok(ConcurrencyAdmission::ActorBudgetExceeded {
                            kind: "per_hour",
                            limit: i64::from(limit),
                            count,
                        });
                    }
                }
                if let Some(limit) = total {
                    let count: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM workflow_executions WHERE actor_id = $1",
                    )
                    .bind(aid)
                    .fetch_one(&mut *tx)
                    .await?;
                    if count >= i64::from(limit) {
                        tx.rollback().await?;
                        return Ok(ConcurrencyAdmission::ActorBudgetExceeded {
                            kind: "total",
                            limit: i64::from(limit),
                            count,
                        });
                    }
                }
                // Rolling per-hour FUEL cap. Sums fuel already consumed by the
                // actor's executions in the last hour (execution_cost_rollup is
                // written per-node during execution by talos-engine's node_hook;
                // it carries actor_id + recorded_at and is covered by the partial
                // index idx_cost_rollup_actor). Pre-execution gate: refuse to
                // START another run once the actor has burned its hourly fuel
                // budget. fuel_consumed/cap are i64 (bigint); the cap can exceed
                // i32, which is why ActorBudgetExceeded.limit is i64.
                if let Some(limit) = fuel_per_hour {
                    // `::bigint` cast is required: Postgres SUM(bigint) returns
                    // NUMERIC, which sqlx can't decode into i64 — without the
                    // cast the whole create transaction errors out.
                    let used: i64 = sqlx::query_scalar(
                        "SELECT COALESCE(SUM(fuel_consumed), 0)::bigint FROM execution_cost_rollup \
                         WHERE actor_id = $1 AND recorded_at > now() - INTERVAL '1 hour'",
                    )
                    .bind(aid)
                    .fetch_one(&mut *tx)
                    .await?;
                    if used >= limit {
                        tx.rollback().await?;
                        return Ok(ConcurrencyAdmission::ActorBudgetExceeded {
                            kind: "fuel_per_hour",
                            limit,
                            count: used,
                        });
                    }
                }
                // R2 token ledger: rolling daily LLM token ceiling. Sums the
                // actor's provider-reported tokens (prompt + completion) from
                // the `llm_usage` ledger over the trailing 24 hours —
                // populated at result-ingest from the SIGNED
                // JobResult/PipelineJobResult, attributed from controller
                // records. Pre-execution gate mirroring `fuel_per_hour`:
                // refuse to START another run once the ceiling is reached.
                // Same `::bigint` cast rationale as the fuel sum above
                // (SUM(bigint) → NUMERIC otherwise).
                if let Some(limit) = llm_tokens_per_day {
                    let used: i64 = sqlx::query_scalar(
                        "SELECT COALESCE(SUM(prompt_tokens + completion_tokens), 0)::bigint \
                         FROM llm_usage \
                         WHERE actor_id = $1 AND recorded_at > now() - INTERVAL '24 hours'",
                    )
                    .bind(aid)
                    .fetch_one(&mut *tx)
                    .await?;
                    if used >= limit {
                        tx.rollback().await?;
                        return Ok(ConcurrencyAdmission::ActorBudgetExceeded {
                            kind: "llm_tokens_per_day",
                            limit,
                            count: used,
                        });
                    }
                }
            }
        }

        // Lock the workflow row. Concurrent triggers against the same
        // workflow_id wait here until our transaction commits (or
        // rolls back). T5-N3 / T7-N1: gate on `user_id = $2` here so a
        // foreign workflow_id fails fast (fetch_one returns NoRowsFound)
        // instead of locking the foreign row and then mismatching at
        // INSERT time. fetch_one rather than fetch_optional: if the
        // workflow row vanished between the caller's validation and
        // here, we'd rather fail closed than INSERT against a missing
        // FK target.
        let max_concurrent: Option<i32> = sqlx::query_scalar(
            "SELECT max_concurrent_executions FROM workflows \
             WHERE id = $1 AND user_id = $2 FOR UPDATE",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;

        // T5-N3 / T7-N1: if a parent_execution_id is provided, verify
        // it belongs to the same user. Audit lineage stays scoped to
        // the user; a foreign parent_execution_id fails closed.
        if let Some(parent_id) = parent_execution_id {
            let owned: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM workflow_executions \
                 WHERE id = $1 AND user_id = $2)",
            )
            .bind(parent_id)
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
            if !owned {
                tx.rollback().await?;
                anyhow::bail!(
                    "create_execution_under_concurrency_limit: parent_execution_id \
                     {parent_id} does not belong to user_id {user_id}"
                );
            }
        }

        if let Some(limit) = max_concurrent {
            let running: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM workflow_executions \
                 WHERE workflow_id = $1 AND status IN ('running', 'queued', 'pending', 'resuming')",
            )
            .bind(workflow_id)
            .fetch_one(&mut *tx)
            .await?;

            if running >= i64::from(limit) {
                // Roll back so no row is written; the caller decides
                // whether to surface "limit reached" to the user or
                // queue / retry.
                tx.rollback().await?;
                return Ok(ConcurrencyAdmission::LimitReached { limit, running });
            }
        }

        sqlx::query(
            "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, workflow_version_id, status, started_at, priority, actor_id, provenance, parent_execution_id, root_execution_id) \
             VALUES ($1, $2, $3, $4, $10::text, NOW(), $5, $6, $7, $8, $9)",
        )
        .bind(id)
        .bind(workflow_id)
        .bind(user_id)
        .bind(version_id)
        .bind(priority.unwrap_or("normal"))
        .bind(actor_id)
        .bind(provenance)
        .bind(parent_execution_id)
        .bind(root_execution_id)
        .bind(initial_status.as_db_str())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(ConcurrencyAdmission::Created)
    }

    /// Batched admission gate for `enqueue_workflow`. Locks the workflow
    /// row, counts in-flight ('running' / 'queued' / 'pending') executions,
    /// and inserts up to `inputs.len()` `'queued'` rows — but never more
    /// than `max_concurrent_executions - currently_in_flight` would allow.
    ///
    /// Without this gate, a single `enqueue_workflow(inputs=[...])` call
    /// blasted N `'queued'` rows past the cap. Because the cap query
    /// (`status IN ('running','queued','pending','resuming')`) counts queued rows,
    /// every other dispatch path (`trigger_workflow`, `bulk_trigger`)
    /// then refused with `LimitReached` for the duration of the drain
    /// — minutes to tens of minutes for a 10K-input batch. Pre-cap'ing
    /// the batch keeps the cap a real budget.
    ///
    /// Returns the admitted prefix of `exec_ids` (in input order — the
    /// suffix is rejected). On `Ok`:
    /// * `inserted = exec_ids.len()` → full admission.
    /// * `inserted < exec_ids.len()` → partial admission; suffix
    ///    rejected because the cap would have been exceeded.
    /// * `inserted = 0` → already at or above cap.
    pub async fn create_executions_batch_under_concurrency_limit(
        &self,
        exec_ids: &[Uuid],
        wf_id: Uuid,
        user_id: Uuid,
        version_id: Option<Uuid>,
        actor_id: Option<Uuid>,
    ) -> Result<BatchAdmission> {
        if exec_ids.is_empty() {
            return Ok(BatchAdmission {
                inserted: 0,
                limit: None,
                running: 0,
            });
        }
        let mut tx = self.db_pool.begin().await?;

        // Lock the workflow row so concurrent enqueues against the same
        // workflow can't both pass the cap check and then both insert.
        let max_concurrent: Option<i32> = sqlx::query_scalar(
            "SELECT max_concurrent_executions FROM workflows \
             WHERE id = $1 AND user_id = $2 FOR UPDATE",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;

        let running: i64 = if max_concurrent.is_some() {
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM workflow_executions \
                 WHERE workflow_id = $1 AND status IN ('running', 'queued', 'pending', 'resuming')",
            )
            .bind(wf_id)
            .fetch_one(&mut *tx)
            .await?
        } else {
            0
        };

        let admit_count: usize = compute_batch_admit_count(max_concurrent, running, exec_ids.len());

        if admit_count == 0 {
            tx.rollback().await?;
            return Ok(BatchAdmission {
                inserted: 0,
                limit: max_concurrent,
                running,
            });
        }

        let admit_slice = &exec_ids[..admit_count];
        sqlx::query(
            "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, status, started_at, workflow_version_id, actor_id) \
             SELECT eid, $2, $3, 'queued', NOW(), $4, $5 \
             FROM UNNEST($1::uuid[]) AS eid",
        )
        .bind(admit_slice)
        .bind(wf_id)
        .bind(user_id)
        .bind(version_id)
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        // Emit one event per admitted row so the dashboard's GraphQL
        // subscription surfaces the queued executions in real time.
        // Mirrors the pattern in
        // `ExecutionRepository::create_executions_batch_for_workflow`.
        if let Some(ref tx_chan) = self.workflow_execution_tx {
            let started_at = chrono::Utc::now().to_rfc3339();
            for &exec_id in admit_slice {
                let _ = tx_chan.send(talos_engine_events::WorkflowExecutionEvent {
                    workflow_id: wf_id,
                    execution_id: exec_id,
                    user_id,
                    status: "queued".to_string(),
                    started_at: started_at.clone(),
                    error_message: None,
                });
            }
        }

        Ok(BatchAdmission {
            inserted: admit_count,
            limit: max_concurrent,
            running,
        })
    }

    /// Insert a new workflow execution record with optional provenance lineage links.
    ///
    /// T5-N3 / T7-N1: defense-in-depth ownership gates at the SQL layer.
    /// (1) The INSERT is rewritten as `INSERT ... SELECT ... WHERE EXISTS`
    ///     so the row only lands when `(workflow_id, user_id)` matches an
    ///     actual workflow. Caller-side ownership checks remain canonical;
    ///     this catches a missed check by silently producing zero rows
    ///     instead of writing an execution row whose `user_id` and the
    ///     workflow's owner disagree.
    /// (2) When `parent_execution_id` is supplied, the same EXISTS gate
    ///     verifies the parent execution belongs to `user_id`, preventing
    ///     a foreign parent from being threaded into the audit lineage.
    ///
    /// Returns `Ok(rows_affected)` so callers can detect the
    /// "ownership mismatch" case (== 0).
    #[allow(clippy::too_many_arguments)]
    pub async fn create_execution_with_lineage(
        &self,
        id: Uuid,
        workflow_id: Uuid,
        user_id: Uuid,
        version_id: Option<Uuid>,
        priority: Option<&str>,
        actor_id: Option<Uuid>,
        provenance: Option<&serde_json::Value>,
        parent_execution_id: Option<Uuid>,
        root_execution_id: Option<Uuid>,
    ) -> Result<u64> {
        let result = sqlx::query(
            "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, workflow_version_id, status, started_at, \
              priority, actor_id, provenance, parent_execution_id, root_execution_id) \
             SELECT $1, $2, $3, $4, 'running', NOW(), $5, $6, $7, $8, $9 \
             WHERE EXISTS (SELECT 1 FROM workflows WHERE id = $2 AND user_id = $3) \
               AND ($8::uuid IS NULL OR EXISTS ( \
                   SELECT 1 FROM workflow_executions \
                   WHERE id = $8 AND user_id = $3 \
               ))",
        )
        .bind(id)
        .bind(workflow_id)
        .bind(user_id)
        .bind(version_id)
        .bind(priority.unwrap_or("normal"))
        .bind(actor_id)
        .bind(provenance)
        .bind(parent_execution_id)
        .bind(root_execution_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Insert a test execution record (flagged with is_test_execution = true).
    pub async fn create_test_execution(
        &self,
        id: Uuid,
        workflow_id: Uuid,
        user_id: Uuid,
        version_id: Option<Uuid>,
        priority: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, workflow_version_id, status, started_at, priority, is_test_execution) \
             VALUES ($1, $2, $3, $4, 'running', NOW(), $5, true)",
        )
        .bind(id)
        .bind(workflow_id)
        .bind(user_id)
        .bind(version_id)
        .bind(priority)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Transition a `queued` execution to `running`. Returns `true` if a row
    /// was promoted, `false` if the execution was not `queued` (already
    /// running/terminal, or claimed by another dispatcher).
    ///
    /// The GraphQL `trigger_workflow` path creates the row as `queued` and
    /// dispatches the engine in a `tokio::spawn`; it MUST call this before the
    /// engine runs. Otherwise the row stays `queued`, and the success-path
    /// `mark_execution_completed` (guarded `WHERE status = 'running'`) silently
    /// no-ops — leaving every successful run stuck at `queued` until the
    /// stuck-execution sweep force-fails it. Mirrors
    /// `ExecutionRepository::mark_execution_running_from_queued` (the
    /// `enqueue_workflow` dispatch path); kept here so this crate's callers
    /// don't take a dependency on `talos-execution-repository`.
    pub async fn mark_execution_running_from_queued(&self, execution_id: Uuid) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE workflow_executions SET status = 'running', started_at = NOW() \
             WHERE id = $1 AND status = 'queued'",
        )
        .bind(execution_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Mark an execution as completed with its output JSON.
    ///
    /// N T5-N1: encrypts `output_data` at rest when `with_encryption`
    /// is wired (matching `ExecutionRepository::mark_execution_completed`
    /// and `ActorRepository::complete_execution`). The plaintext branch
    /// NULLs the ciphertext columns symmetrically so a row previously
    /// written via the encrypted path then re-written via the plaintext
    /// path doesn't keep stale ciphertext that subsequent encryption-aware
    /// reads would prefer.
    pub async fn mark_execution_completed(
        &self,
        execution_id: Uuid,
        output: &serde_json::Value,
    ) -> Result<()> {
        // MCP-1204 (2026-05-17): bound the output at the entry boundary
        // so the encrypted-branch serialise + AES-GCM allocation AND
        // the plaintext-branch redact_json regex walk both run against
        // the bounded value. Over-cap payloads collapse to a small
        // sentinel JSON object describing the truncation.
        let bounded = bound_execution_payload(output);
        let output = &*bounded;
        if let Some((key_id, enc_bytes, format_version)) = self
            .maybe_encrypt_execution_output(execution_id, output)
            .await?
        {
            sqlx::query(
                "UPDATE workflow_executions \
                 SET status = 'completed', output_data = NULL, \
                     output_data_enc = $1, output_enc_key_id = $2, \
                     output_data_format = $3, completed_at = NOW() \
                 WHERE id = $4 AND status IN ('running', 'resuming')",
            )
            .bind(&enc_bytes)
            .bind(key_id)
            .bind(format_version)
            .bind(execution_id)
            .execute(&self.db_pool)
            .await?;
        } else {
            // MCP-971 (2026-05-15): DLP-redact the plaintext fallback
            // output before bind. The encrypt branch above is the
            // production path; this `else` only fires when
            // SecretsManager isn't wired (test envs, post-rotate ad-
            // hoc fixes, migrations). The persistence-boundary DLP
            // rule (MCP-466/481-484 family) applies to BOTH branches
            // — `redact_json` is the right call on plaintext output
            // even though it's the defence-in-depth path. `redact_str`
            // is infallible, `redact_json` is too (walks the tree).
            let redacted = talos_dlp_provider::redact_json(output);
            sqlx::query(
                "UPDATE workflow_executions \
                 SET status = 'completed', output_data = $1, \
                     output_data_enc = NULL, output_enc_key_id = NULL, \
                     completed_at = NOW() \
                 WHERE id = $2 AND status IN ('running', 'resuming')",
            )
            .bind(&redacted)
            .bind(execution_id)
            .execute(&self.db_pool)
            .await?;
        }
        Ok(())
    }

    /// Mark an execution as waiting — the engine returned `ctx.waiting = true`
    /// because a Wait node is paused for an external resume signal. Mirrors
    /// the raw-SQL path in `scheduler.rs` around the engine-finished branch.
    /// The execution stays in the DB until `resume_workflow_by_correlation_id`
    /// (or equivalent) advances it.
    ///
    /// N T5-N1: encryption symmetry as for `mark_execution_completed`.
    pub async fn mark_execution_waiting(
        &self,
        execution_id: Uuid,
        output: &serde_json::Value,
    ) -> Result<()> {
        // MCP-1204: same bound as mark_execution_completed. Wait-node
        // outputs commonly carry the HTTP callback request body from
        // upstream services, so the same multi-MB risk applies.
        let bounded = bound_execution_payload(output);
        let output = &*bounded;
        if let Some((key_id, enc_bytes, format_version)) = self
            .maybe_encrypt_execution_output(execution_id, output)
            .await?
        {
            sqlx::query(
                "UPDATE workflow_executions \
                 SET status = 'waiting', output_data = NULL, \
                     output_data_enc = $1, output_enc_key_id = $2, \
                     output_data_format = $3 \
                 WHERE id = $4 AND status IN ('running', 'resuming')",
            )
            .bind(&enc_bytes)
            .bind(key_id)
            .bind(format_version)
            .bind(execution_id)
            .execute(&self.db_pool)
            .await?;
        } else {
            // MCP-972 (2026-05-15): same plaintext-fallback DLP fix
            // as the completed/failed siblings (MCP-971). Wait-node
            // outputs commonly carry response bodies from upstream
            // services (the Wait node typically pauses on an HTTP
            // callback), so the same arbitrary-text DLP class applies.
            let redacted = talos_dlp_provider::redact_json(output);
            sqlx::query(
                "UPDATE workflow_executions \
                 SET status = 'waiting', output_data = $1, \
                     output_data_enc = NULL, output_enc_key_id = NULL \
                 WHERE id = $2 AND status IN ('running', 'resuming')",
            )
            .bind(&redacted)
            .bind(execution_id)
            .execute(&self.db_pool)
            .await?;
        }
        Ok(())
    }

    /// Mark an execution as failed with an error message and optional output.
    ///
    /// N T5-N1: encryption symmetry as for `mark_execution_completed`.
    /// `output: None` writes both ciphertext columns NULL on the
    /// encrypted branch (no output to encrypt) AND clears the plaintext
    /// column on the plaintext branch.
    pub async fn mark_execution_failed(
        &self,
        execution_id: Uuid,
        error: &str,
        output: Option<&serde_json::Value>,
    ) -> Result<()> {
        // MCP-967 (2026-05-15): DLP-redact the error string before
        // persistence. Pre-fix `error` came directly from engine
        // failure paths (node exceptions, HTTP response bodies,
        // upstream API error strings — same arbitrary-text class as
        // `log_message` covered by MCP-965/966) and was bound
        // straight into `workflow_executions.error_message` without
        // scrubbing. Secrets matching `sk-*`, `ghp_*`, Bearer tokens,
        // etc. that appeared in the failure surface (HTTP 401
        // response bodies echoing the offending Authorization
        // header, GraphQL error responses with auth context, etc.)
        // landed in the DB unredacted. Output side is already covered
        // by `maybe_encrypt_execution_output` above; error_message
        // was the gap. `redact_str` is infallible.
        //
        // MCP-1161 (2026-05-17): truncate-then-redact discipline.
        // Some callers pre-redact (e.g. `talos-execution-orchestration::
        // trigger.rs:551` runs `redact_str(e.to_string())` before
        // calling here), but the engine error `e.to_string()` is
        // unbounded — wasmtime traces and NATS-relayed upstream
        // HTTP response bodies can be multi-MB. Pre-fix the DLP
        // regex pass walked the full string AND the unbounded
        // result landed in `workflow_executions.error_message` which
        // has no DB-side length cap. Sibling drift to MCP-1012
        // (auth_audit_log) / MCP-1018 (webhook_request_log user_agent)
        // / MCP-1027/1028 (oauth + slack + gmail audit_log) /
        // MCP-1160 (webhook_request_log response_body+error_message).
        // 4 KiB matches the MCP-1160 error_message ceiling; covers
        // every legitimate engine/wasmtime trace + headroom.
        let truncated_error: &str = if error.len() > 4096 {
            talos_text_util::truncate_at_char_boundary(error, 4096)
        } else {
            error
        };
        let redacted_error = talos_dlp_provider::redact_str(truncated_error);
        // MCP-1204: bound the optional output before both branches.
        let bounded_output = output.map(bound_execution_payload);
        let output: Option<&serde_json::Value> = bounded_output.as_ref().map(|c| c.as_ref());
        // Optional encryption: only encrypt if SM is wired AND we have output.
        let encrypted = match (self.secrets_manager.as_ref(), output) {
            (Some(_), Some(out)) => {
                self.maybe_encrypt_execution_output(execution_id, out)
                    .await?
            }
            _ => None,
        };
        if self.secrets_manager.is_some() {
            // Encrypted-aware branch: writes ciphertext when present,
            // NULLs plaintext column unconditionally so a stale value
            // can't survive a fail-rewrite. MCP-S2: format_version is
            // always written (v1 when encrypting, v1 sentinel when not)
            // so the column invariant holds.
            let (enc_bytes, enc_key_id, enc_format) = match encrypted {
                Some((kid, bytes, version)) => (Some(bytes), Some(kid), version),
                None => (
                    None,
                    None,
                    talos_secrets_manager::SecretsManager::AAD_FORMAT_V1,
                ),
            };
            sqlx::query(
                "UPDATE workflow_executions \
                 SET status = 'failed', error_message = $1, output_data = NULL, \
                     output_data_enc = $2, output_enc_key_id = $3, \
                     output_data_format = $4, completed_at = NOW() \
                 WHERE id = $5 AND status IN ('running', 'resuming')",
            )
            .bind(&redacted_error)
            .bind(enc_bytes.as_deref())
            .bind(enc_key_id)
            .bind(enc_format)
            .bind(execution_id)
            .execute(&self.db_pool)
            .await?;
        } else {
            // MCP-971: DLP-redact the plaintext fallback output. Same
            // defence-in-depth as mark_execution_completed above. The
            // Option<&Value> is mapped through `redact_json` to preserve
            // None semantics (clears the column).
            let redacted_output = output.map(talos_dlp_provider::redact_json);
            sqlx::query(
                "UPDATE workflow_executions \
                 SET status = 'failed', error_message = $1, output_data = $2, \
                     output_data_enc = NULL, output_enc_key_id = NULL, \
                     completed_at = NOW() \
                 WHERE id = $3 AND status IN ('running', 'resuming')",
            )
            .bind(&redacted_error)
            .bind(redacted_output.as_ref())
            .bind(execution_id)
            .execute(&self.db_pool)
            .await?;
        }
        Ok(())
    }

    /// Cancel all still-running module_executions for a workflow execution.
    /// Called after marking a workflow as failed so that parallel siblings
    /// that were in-flight are cleaned up.  The DB trigger
    /// `trg_cancel_siblings_on_workflow_fail` (migration 20260327000001) handles
    /// this atomically, but this explicit call is defence-in-depth for environments
    /// where the trigger has not yet been applied.
    pub async fn cancel_running_module_executions(&self, execution_id: Uuid) -> Result<()> {
        let result = sqlx::query(
            "UPDATE module_executions \
             SET status = 'cancelled', completed_at = NOW(), \
                 error_message = 'Workflow failed — parallel sibling cancelled' \
             WHERE workflow_execution_id = $1 AND status = 'running'",
        )
        .bind(execution_id)
        .execute(&self.db_pool)
        .await?;
        tracing::info!(
            execution_id = %execution_id,
            cancelled = result.rows_affected(),
            "sibling cancellation UPDATE complete"
        );
        Ok(())
    }

    /// Record a workflow reuse event (best-effort telemetry).
    pub async fn record_reuse_event(&self, workflow_id: Uuid, invocation_type: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO workflow_reuse_events (workflow_id, invocation_type) VALUES ($1, $2)",
        )
        .bind(workflow_id)
        .bind(invocation_type)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Update the status/output/error of an existing execution record.
    ///
    /// N T5-N1: encryption symmetry as for `mark_execution_completed`.
    pub async fn update_execution_output(
        &self,
        execution_id: Uuid,
        status: &str,
        output: Option<&serde_json::Value>,
        error: Option<&str>,
    ) -> Result<()> {
        // MCP-972 (2026-05-15): generic status/output/error updater
        // had a DLP gap in BOTH branches: `error` was bound raw in
        // both the encrypted-output AND plaintext-output paths,
        // and the plaintext path also bound `output` directly.
        // Same arbitrary-text DLP class as MCP-967/971; pre-fix
        // tools writing to this method (status transitions outside
        // of the canonical mark_completed/mark_failed paths) leaked
        // unscrubbed text into error_message + output_data. Redact
        // both at the bind boundary.
        let redacted_error = error.map(talos_dlp_provider::redact_str);
        // MCP-1204: bound the optional output before both branches —
        // sibling to mark_execution_failed above.
        let bounded_output = output.map(bound_execution_payload);
        // Redact the output ONCE, up front, so BOTH branches store the scrubbed
        // value. The encrypted branch previously fed `output` straight to
        // `maybe_encrypt_execution_output` with no `redact_json` — contradicting
        // this method's own docstring — so a secret-bearing output was encrypted
        // UNREDACTED and decrypted back to clients on read. Encryption-at-rest
        // is not a substitute for DLP (it protects a DB dump, not the
        // decrypt-on-read path). This method currently has no callers; the fix
        // keeps the latent path honest before one is added.
        let redacted_output: Option<serde_json::Value> = bounded_output
            .as_ref()
            .map(|c| talos_dlp_provider::redact_json(c.as_ref()));
        let output: Option<&serde_json::Value> = redacted_output.as_ref();
        let encrypted = match (self.secrets_manager.as_ref(), output) {
            (Some(_), Some(out)) => {
                self.maybe_encrypt_execution_output(execution_id, out)
                    .await?
            }
            _ => None,
        };
        if self.secrets_manager.is_some() {
            let (enc_bytes, enc_key_id, enc_format) = match encrypted {
                Some((kid, bytes, version)) => (Some(bytes), Some(kid), version),
                None => (
                    None,
                    None,
                    talos_secrets_manager::SecretsManager::AAD_FORMAT_V1,
                ),
            };
            sqlx::query(
                "UPDATE workflow_executions \
                 SET status = $1, output_data = NULL, \
                     output_data_enc = $2, output_enc_key_id = $3, \
                     output_data_format = $4, \
                     error_message = $5, completed_at = NOW() \
                 WHERE id = $6 AND status IN ('running', 'resuming')",
            )
            .bind(status)
            .bind(enc_bytes.as_deref())
            .bind(enc_key_id)
            .bind(enc_format)
            .bind(redacted_error.as_deref())
            .bind(execution_id)
            .execute(&self.db_pool)
            .await?;
        } else {
            // `output` is already DLP-redacted above (shared by both branches).
            sqlx::query(
                "UPDATE workflow_executions \
                 SET status = $1, output_data = $2, \
                     output_data_enc = NULL, output_enc_key_id = NULL, \
                     error_message = $3, completed_at = NOW() \
                 WHERE id = $4 AND status IN ('running', 'resuming')",
            )
            .bind(status)
            .bind(output)
            .bind(redacted_error.as_deref())
            .bind(execution_id)
            .execute(&self.db_pool)
            .await?;
        }
        Ok(())
    }

    // ── Actor / budget policy ──────────────────────────────────────────────

    /// Fetch an actor record with its budget policy. Returns None if not found / wrong owner.
    pub async fn get_actor(&self, actor_id: Uuid, user_id: Uuid) -> Result<Option<ActorRow>> {
        let row = sqlx::query(
            "SELECT a.id, a.name, a.status, a.is_default, \
                    abp.max_workflow_count, abp.max_executions_per_hour, \
                    abp.max_executions_total \
             FROM actors a \
             LEFT JOIN actor_budget_policies abp ON abp.actor_id = a.id \
             WHERE a.id = $1 AND a.user_id = $2",
        )
        .bind(actor_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        row.map(|r| -> Result<ActorRow> {
            Ok(ActorRow {
                id: r.try_get("id")?,
                name: r.try_get("name")?,
                status: r.try_get("status")?,
                max_workflow_count: r.try_get::<Option<_>, _>("max_workflow_count")?,
                max_executions_per_hour: r.try_get::<Option<_>, _>("max_executions_per_hour")?,
                max_executions_total: r.try_get::<Option<_>, _>("max_executions_total")?,
                is_default: r.try_get::<Option<_>, _>("is_default")?.unwrap_or(false),
            })
        })
        .transpose()
    }

    /// Resolve a WORKFLOW's bound actor's privilege ceilings
    /// (`max_llm_tier`, `max_write_ceiling`) in ONE narrow query, scoped to
    /// `user_id` on BOTH the workflow and the actor. Returns `Ok(None)` when
    /// the workflow isn't visible to the user, has no bound actor, or the
    /// actor isn't owned by the user — the fail-closed tenancy contract.
    ///
    /// Used by the sub-workflow dispatch path to narrow the sub-engine to
    /// `most_restrictive(parent, sub-actor)` on each axis. Deliberately a
    /// single JOIN that never touches `graph_json`: the first-cut resolver
    /// called `get_workflow` (15 columns incl. the full graph, inside an RLS
    /// transaction) just to read `actor_id`, then a second query for the
    /// ceilings — a per-sub-dispatch regression a perf review caught (a
    /// 5-iteration reflective-retry did 9 redundant heavy fetches). Both
    /// columns parse through the fail-closed `from_db_str` helpers (unknown /
    /// malformed values → `Tier1` / `ReadOnly`), so column drift can never
    /// widen a sub-workflow's authority.
    pub async fn get_workflow_actor_ceilings(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<
        Option<(
            talos_workflow_engine_core::LlmTier,
            talos_workflow_engine_core::WriteCeiling,
        )>,
    > {
        let row = sqlx::query(
            "SELECT a.max_llm_tier, a.max_write_ceiling \
             FROM workflows w \
             JOIN actors a ON a.id = w.actor_id \
             WHERE w.id = $1 AND w.user_id = $2 AND a.user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        row.map(|r| -> Result<_> {
            let tier = talos_workflow_engine_core::LlmTier::from_db_str(
                &r.try_get::<String, _>("max_llm_tier")?,
            );
            let ceiling = talos_workflow_engine_core::WriteCeiling::from_db_str(
                &r.try_get::<String, _>("max_write_ceiling")?,
            );
            Ok((tier, ceiling))
        })
        .transpose()
    }

    /// Count non-archived workflows owned by an actor.
    pub async fn count_actor_workflows(&self, actor_id: Uuid) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM workflows \
             WHERE actor_id = $1 AND (status IS NULL OR status != 'archived')",
        )
        .bind(actor_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    /// Count executions triggered by an actor in the past hour.
    pub async fn count_actor_executions_last_hour(&self, actor_id: Uuid) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM workflow_executions \
             WHERE actor_id = $1 AND started_at >= NOW() - INTERVAL '1 hour'",
        )
        .bind(actor_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    // `get_actor_memories` (previously reading a non-existent
    // `actor_memories` table — note the plural — same misnomer that
    // bit `upsert_actor_memory` below) was dead code and has been
    // removed. For live reads use `talos_memory::list_memories` or
    // `recall_exact` against the canonical `actor_memory` (singular)
    // table.

    // `upsert_actor_memory` (previously writing to a non-existent
    // `actor_memories` table) was dead code and has been removed.
    // Use `talos_memory::persist_memory` for memory writes.

    // ── Alerts & webhooks ──────────────────────────────────────────────────

    /// Fetch the failure webhook URL configured for a workflow.
    pub async fn get_failure_webhook_url(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        let url: Option<String> = sqlx::query_scalar(
            "SELECT url FROM workflow_webhooks \
             WHERE workflow_id = $1 AND user_id = $2 AND event_type = 'execution_failed' \
             LIMIT 1",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(url)
    }

    /// Upsert a workflow execution failure alert (occurrence-count style).
    pub async fn upsert_execution_failure_alert(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        execution_id: Uuid,
        message: &str,
    ) -> Result<()> {
        // N-L (2026-05-06): snapshot the workflow name into the alert
        // row at INSERT time via a sub-SELECT, so post-delete reads
        // surface the original name instead of "unknown". The
        // sub-SELECT runs once per INSERT (cheap; bypasses the
        // LATERAL JOIN at read time), and ON CONFLICT preserves the
        // existing snapshot — if the workflow is renamed AFTER the
        // first alert, subsequent occurrences still reference the
        // name in effect when the alert chain started, which matches
        // operator expectations (consistent context per alert chain).
        sqlx::query(
            "INSERT INTO workflow_alerts (user_id, workflow_id, execution_id, message, workflow_name) \
             VALUES ($1, $2, $3, $4, (SELECT name FROM workflows WHERE id = $2)) \
             ON CONFLICT (workflow_id, message) WHERE acknowledged = false DO UPDATE \
             SET occurrence_count = workflow_alerts.occurrence_count + 1, \
                 last_occurred_at = NOW(), \
                 execution_id = EXCLUDED.execution_id, \
                 acknowledged = false",
        )
        .bind(user_id)
        .bind(workflow_id)
        .bind(execution_id)
        .bind(message)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Fetch the failure_webhook_url column directly from the workflows table.
    /// (Distinct from `get_failure_webhook_url` which queries workflow_webhooks.)
    pub async fn get_workflow_failure_webhook(&self, workflow_id: Uuid) -> Result<Option<String>> {
        let url: Option<String> =
            sqlx::query_scalar("SELECT failure_webhook_url FROM workflows WHERE id = $1")
                .bind(workflow_id)
                .fetch_optional(&self.db_pool)
                .await?
                .flatten();
        Ok(url)
    }

    /// Count of completed executions for a workflow, regardless of
    /// output_data presence. Used by `get_workflow_input_schema` to expose
    /// the gap between "successful executions overall" and "executions
    /// with output_data we could analyze," so a small inference sample
    /// size is self-explanatory rather than confusing.
    pub async fn count_completed_executions(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 AND status = 'completed'",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    /// Recent successful executions' `output_data` for a workflow. Used by
    /// `get_workflow_input_schema` to infer the input shape from real history.
    ///
    /// MCP-680 (2026-05-13): pre-fix the SELECT pulled only the plaintext
    /// `output_data` column and filtered `output_data IS NOT NULL`. With
    /// SecretsManager wired (the production default), every encrypted
    /// completed-execution row has `output_data = NULL` (the ciphertext
    /// lives in `output_data_enc + output_enc_key_id`) — so the filter
    /// skipped ALL of them and `get_workflow_input_schema` reported "no
    /// example data" even when the workflow had completed runs. Sibling
    /// fix to `list_completed_workflow_executions_with_output` in
    /// talos-module-repository. Same shape: SELECT both column families,
    /// decrypt via SecretsManager when ciphertext is present, fall back
    /// to plaintext for legacy rows.
    pub async fn list_recent_completed_outputs(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<serde_json::Value>> {
        // MCP-S2: SELECT `id` + `output_data_format` so the decrypt
        // dispatcher can route v1 rows through the AAD path. Legacy v0
        // rows naturally fall through to the empty-AAD path.
        let raw: Vec<(
            Uuid,
            Option<serde_json::Value>,
            Option<Vec<u8>>,
            Option<Uuid>,
            i16,
        )> = sqlx::query_as(
            "SELECT id, output_data, output_data_enc, output_enc_key_id, output_data_format \
             FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 AND status = 'completed' \
               AND (output_data IS NOT NULL OR output_data_enc IS NOT NULL) \
             ORDER BY started_at DESC LIMIT $3",
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        let mut out = Vec::with_capacity(raw.len());
        for (exec_id, plaintext, enc_bytes, key_id, format_version) in raw {
            let value = match (&self.secrets_manager, enc_bytes, key_id) {
                (Some(sm), Some(bytes), Some(kid)) => {
                    match sm
                        .decrypt_versioned(kid, &bytes, exec_id.as_bytes(), format_version)
                        .await
                    {
                        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|_| serde_json::json!({})),
                        Err(e) => {
                            tracing::warn!(
                                err = ?e,
                                "list_recent_completed_outputs: decrypt failed — skipping row"
                            );
                            continue;
                        }
                    }
                }
                _ => plaintext.unwrap_or(serde_json::json!({})),
            };
            out.push(value);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod execution_output_cap_tests {
    use talos_dlp_provider::{bound_execution_payload, MAX_EXECUTION_PAYLOAD_BYTES};

    #[test]
    fn under_cap_passes_through_borrowed() {
        // MCP-1204: typical workflow output (small structured JSON)
        // must pass through as Cow::Borrowed — zero clone cost on the
        // happy path.
        let v = serde_json::json!({ "summary": "ok", "rows_processed": 42 });
        let bounded = bound_execution_payload(&v);
        assert!(matches!(bounded, std::borrow::Cow::Borrowed(_)));
        assert_eq!(&*bounded, &v);
    }

    #[test]
    fn over_cap_produces_truncation_sentinel() {
        // MCP-1204: payloads above 10 MiB collapse to a sentinel
        // object so execution-completion semantics survive (consumers
        // still get a valid JSON object) while the heap pressure is
        // bounded. The sentinel carries the original size so the
        // operator dashboard can correlate.
        let huge = "x".repeat(MAX_EXECUTION_PAYLOAD_BYTES + 1024);
        let v = serde_json::json!({ "leak": huge });
        let bounded = bound_execution_payload(&v);
        assert!(matches!(bounded, std::borrow::Cow::Owned(_)));
        let owned = bounded.into_owned();
        assert_eq!(owned["_truncated"], serde_json::json!(true));
        let original_size = owned["_original_size_bytes"]
            .as_u64()
            .expect("size must be present");
        assert!(
            original_size > MAX_EXECUTION_PAYLOAD_BYTES as u64,
            "original_size_bytes must exceed the cap: {original_size}"
        );
        assert!(
            owned["_reason"]
                .as_str()
                .map(|s| s.contains("10 MiB"))
                .unwrap_or(false),
            "reason must mention the cap"
        );
    }

    #[test]
    fn at_cap_passes_through() {
        // MCP-1204: boundary check — payload whose serialised form
        // is exactly at the cap must NOT trigger the sentinel (the
        // measure uses `>`, not `>=`).
        let target_size = MAX_EXECUTION_PAYLOAD_BYTES - 32;
        let v = serde_json::json!({ "p": "x".repeat(target_size) });
        let serialized = serde_json::to_string(&v).unwrap();
        assert!(
            serialized.len() <= MAX_EXECUTION_PAYLOAD_BYTES,
            "fixture must fit under cap: {}",
            serialized.len()
        );
        let bounded = bound_execution_payload(&v);
        assert!(matches!(bounded, std::borrow::Cow::Borrowed(_)));
    }
}
