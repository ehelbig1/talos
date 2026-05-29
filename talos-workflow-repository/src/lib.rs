/// WorkflowRepository — centralises all SQL for the workflows domain.
///
/// Follows the ModuleExecutionService pattern: plain struct, `new(db_pool)`,
/// all methods `pub async fn`, return `anyhow::Result<T>` so callers can `?`.
/// Handlers in `mcp/workflows.rs` should be thin wrappers that call these
/// methods and format the JSON-RPC response.
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use talos_dlp_provider::bound_execution_payload;
use uuid::Uuid;

/// MCP-548: decode `allowed_secrets TEXT[]` from a Postgres row, logging
/// loudly on decode failure. The column is `NOT NULL DEFAULT '{}'` so a
/// decode error indicates real schema drift (TEXT[] → JSONB regression,
/// projection-loss, SQLx mapping change). Returning Vec::new() is
/// fail-closed (empty allowed_secrets denies every vault path via
/// `vault_path_permitted`), but the previous silent `unwrap_or_default()`
/// made the symptom indistinguishable from a module installed with no
/// secret grants. Surfacing the sqlx error lets operators tell apart
/// schema drift from a legitimately empty grant. Mirrors the helper
/// in `talos-registry`.
fn decode_allowed_secrets_row(row: &sqlx::postgres::PgRow, context_id: Option<Uuid>) -> Vec<String> {
    match row.try_get::<Vec<String>, _>("allowed_secrets") {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                target: "talos_workflow_repository",
                event_kind = "allowed_secrets_decode_failed",
                context_id = ?context_id,
                error = %e,
                "MCP-548: allowed_secrets column decode failed — falling back to empty (deny-all). \
                 Every vault path will be denied for this module until schema parity is restored."
            );
            Vec::new()
        }
    }
}

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
        assert_eq!(InitialExecutionStatus::default(), InitialExecutionStatus::Running);
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

// ─────────────────────────────────────────────────────────────────────────────
// Row DTOs
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct WorkflowSummary {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    /// Raw JSON string — the handler parses it for node/edge counts.
    pub graph_json: String,
    pub tags: Vec<String>,
    pub last_status: Option<String>,
    pub last_exec_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub status: Option<String>,
    pub workflow_type: Option<String>,
}

#[derive(Debug)]
pub struct WorkflowRecord {
    pub id: Uuid,
    pub name: String,
    pub graph_json: String,
    pub tags: Vec<String>,
    pub description: Option<String>,
    pub max_concurrent_executions: Option<i32>,
    pub is_enabled: bool,
    pub capabilities: Vec<String>,
    pub intent: Option<serde_json::Value>,
    pub readiness_score: Option<i32>,
    pub actor_id: Option<Uuid>,
    pub status: Option<String>,
    pub workflow_type: Option<String>,
    pub timeout_seconds: Option<i32>,
    pub input_schema: Option<serde_json::Value>,
}

#[derive(Debug)]
pub struct ActorRow {
    pub id: Uuid,
    pub name: String,
    pub status: String,
    pub max_workflow_count: Option<i32>,
    pub max_executions_per_hour: Option<i32>,
    pub max_executions_total: Option<i64>,
}

// `ActorMemory` struct removed alongside its sole consumer
// `get_actor_memories` (read from non-existent `actor_memories`
// plural table). For live reads use `talos_memory::list_memories`.

// ─────────────────────────────────────────────────────────────────────────────
// Repository
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct WorkflowRepository {
    db_pool: PgPool,
    /// Optional SecretsManager. When wired (`with_encryption`), the
    /// `mark_execution_*` and `update_execution_output` methods encrypt
    /// `output_data` at rest the same way `ExecutionRepository` and
    /// `ActorRepository::complete_execution` do (N T5-N1). Without this
    /// hook the methods fall back to plaintext writes — the historical
    /// behavior — but a row that was previously written via the
    /// encrypted path then re-written via the plaintext path keeps its
    /// stale ciphertext, so the encrypted branch's read order
    /// (ciphertext preferred when both columns are populated) would
    /// surface OLD output. The plaintext branch therefore NULLs the
    /// ciphertext columns symmetrically.
    secrets_manager: Option<std::sync::Arc<talos_secrets_manager::SecretsManager>>,
    /// Optional broadcast channel for newly-created execution rows.
    /// Mirrors `ExecutionRepository::workflow_execution_tx` — the
    /// cap-aware batch admission helper emits one event per admitted
    /// row so GraphQL subscribers see queued executions appear in the
    /// dashboard. Without this hook the helper still works, just
    /// without real-time notifications.
    workflow_execution_tx:
        Option<tokio::sync::broadcast::Sender<talos_engine_events::WorkflowExecutionEvent>>,
}

impl WorkflowRepository {
    pub fn new(db_pool: PgPool) -> Self {
        Self {
            db_pool,
            secrets_manager: None,
            workflow_execution_tx: None,
        }
    }

    /// Builder: attach SecretsManager so `mark_execution_*` and
    /// `update_execution_output` encrypt `output_data` at rest. Mirrors
    /// `ActorRepository::with_encryption` and the equivalent helper on
    /// `ExecutionRepository`. Wiring is opt-in so test contexts and
    /// pre-encryption migration paths continue to work unchanged.
    pub fn with_encryption(
        mut self,
        sm: std::sync::Arc<talos_secrets_manager::SecretsManager>,
    ) -> Self {
        self.secrets_manager = Some(sm);
        self
    }

    /// Builder: attach the broadcast channel for execution-creation
    /// events. The cap-aware batch admission helper emits one event
    /// per admitted row.
    pub fn with_workflow_execution_sender(
        mut self,
        tx: tokio::sync::broadcast::Sender<talos_engine_events::WorkflowExecutionEvent>,
    ) -> Self {
        self.workflow_execution_tx = Some(tx);
        self
    }

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
            .encrypt_value_aad_v1(&json_str, exec_id.as_bytes())
            .await?;
        Ok(Some((key_id, enc_bytes, version)))
    }
}

impl WorkflowRepository {

    // ── Listing & retrieval ────────────────────────────────────────────────

    /// List workflows for a user, optionally filtered by tag. Returns up to 50.
    pub async fn list_workflows(
        &self,
        user_id: Uuid,
        tag_filter: Option<&str>,
    ) -> Result<Vec<WorkflowSummary>> {
        let rows = if let Some(tag) = tag_filter {
            sqlx::query(
                "SELECT w.id, w.name, w.description, w.graph_json, w.created_at, w.updated_at, \
                        w.tags, latest.status AS last_status, latest.started_at AS last_exec_at \
                 FROM workflows w \
                 LEFT JOIN LATERAL ( \
                     SELECT status, started_at FROM workflow_executions \
                     WHERE workflow_id = w.id ORDER BY started_at DESC LIMIT 1 \
                 ) latest ON true \
                 WHERE w.user_id = $1 AND $2 = ANY(w.tags) \
                 ORDER BY w.updated_at DESC LIMIT 50",
            )
            .bind(user_id)
            .bind(tag)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                "SELECT w.id, w.name, w.description, w.graph_json, w.created_at, w.updated_at, \
                        w.tags, latest.status AS last_status, latest.started_at AS last_exec_at \
                 FROM workflows w \
                 LEFT JOIN LATERAL ( \
                     SELECT status, started_at FROM workflow_executions \
                     WHERE workflow_id = w.id ORDER BY started_at DESC LIMIT 1 \
                 ) latest ON true \
                 WHERE w.user_id = $1 \
                 ORDER BY w.updated_at DESC LIMIT 50",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await?
        };

        let summaries = rows
            .into_iter()
            .map(|row| WorkflowSummary {
                id: row.get("id"),
                name: row.get("name"),
                description: row.try_get("description").ok().flatten(),
                graph_json: row.get("graph_json"),
                tags: row.try_get("tags").ok().unwrap_or_default(),
                last_status: row.try_get("last_status").ok().flatten(),
                last_exec_at: row.try_get("last_exec_at").ok().flatten(),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                status: row.try_get("status").ok().flatten(),
                workflow_type: row.try_get("workflow_type").ok().flatten(),
            })
            .collect();

        Ok(summaries)
    }

    /// Paginated workflow listing with status + type filters.
    pub async fn list_workflows_paginated(
        &self,
        user_id: Uuid,
        status_filter: Option<&str>,
        type_filter: Option<&str>,
        tag_filter: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<WorkflowSummary>, i64)> {
        let base_select =
            "SELECT w.id, w.name, w.description, w.graph_json, w.created_at, w.updated_at, \
                           w.tags, w.status, w.workflow_type, \
                           latest.status AS last_status, latest.started_at AS last_exec_at";
        let from_clause = "FROM workflows w \
                           LEFT JOIN LATERAL ( \
                               SELECT status, started_at FROM workflow_executions \
                               WHERE workflow_id = w.id ORDER BY started_at DESC LIMIT 1 \
                           ) latest ON true";

        // SECURITY: Build WHERE clause dynamically using ONLY parameterized binds.
        // The format! macro is used ONLY to construct SQL structure ($N placeholders),
        // never for user values. All user-provided values are bound separately via .bind().
        // This prevents SQL injection while allowing dynamic query construction.
        let mut conditions = vec!["w.user_id = $1"];
        let mut param_idx = 2usize;

        let status_clause = status_filter.map(|_| {
            let c = format!("w.status = ${}", param_idx);
            param_idx += 1;
            c
        });
        let type_clause = type_filter.map(|_| {
            let c = format!("w.workflow_type = ${}", param_idx);
            param_idx += 1;
            c
        });
        let tag_clause = tag_filter.map(|_| {
            let c = format!("${} = ANY(w.tags)", param_idx);
            param_idx += 1;
            c
        });
        let limit_param = param_idx;
        param_idx += 1;
        let offset_param = param_idx;

        if let Some(ref c) = status_clause {
            conditions.push(c);
        }
        if let Some(ref c) = type_clause {
            conditions.push(c);
        }
        if let Some(ref c) = tag_clause {
            conditions.push(c);
        }

        let where_str = conditions.join(" AND ");
        let data_sql = format!(
            "{base_select} {from_clause} WHERE {where_str} ORDER BY w.updated_at DESC LIMIT ${limit_param} OFFSET ${offset_param}"
        );
        let count_sql = format!("SELECT COUNT(*) FROM workflows w WHERE {where_str}");

        let mut data_q = sqlx::query(&data_sql).bind(user_id);
        let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql).bind(user_id);
        if let Some(s) = status_filter {
            data_q = data_q.bind(s);
            count_q = count_q.bind(s);
        }
        if let Some(t) = type_filter {
            data_q = data_q.bind(t);
            count_q = count_q.bind(t);
        }
        if let Some(tg) = tag_filter {
            data_q = data_q.bind(tg);
            count_q = count_q.bind(tg);
        }
        data_q = data_q.bind(limit).bind(offset);

        let (rows, total) = tokio::try_join!(
            data_q.fetch_all(&self.db_pool),
            count_q.fetch_one(&self.db_pool),
        )?;

        let summaries = rows
            .into_iter()
            .map(|row| WorkflowSummary {
                id: row.get("id"),
                name: row.get("name"),
                description: row.try_get("description").ok().flatten(),
                graph_json: row.get("graph_json"),
                tags: row.try_get("tags").ok().unwrap_or_default(),
                last_status: row.try_get("last_status").ok().flatten(),
                last_exec_at: row.try_get("last_exec_at").ok().flatten(),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                status: row.try_get("status").ok().flatten(),
                workflow_type: row.try_get("workflow_type").ok().flatten(),
            })
            .collect();

        Ok((summaries, total))
    }

    /// Fetch a full workflow record by id + user_id (ownership check). Returns None if not found.
    pub async fn get_workflow(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WorkflowRecord>> {
        let row = sqlx::query(
            "SELECT id, name, graph_json, tags, description, max_concurrent_executions, \
                    is_enabled, capabilities, intent, readiness_score, actor_id, status, \
                    workflow_type, timeout_seconds, input_schema \
             FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(row.map(|r| WorkflowRecord {
            id: r.get("id"),
            name: r.get("name"),
            graph_json: r.get("graph_json"),
            tags: r.try_get("tags").unwrap_or_default(),
            description: r.try_get("description").unwrap_or(None),
            max_concurrent_executions: r.try_get("max_concurrent_executions").unwrap_or(None),
            is_enabled: r.try_get("is_enabled").unwrap_or(true),
            capabilities: r.try_get("capabilities").unwrap_or_default(),
            intent: r.try_get("intent").unwrap_or(None),
            readiness_score: r.try_get("readiness_score").unwrap_or(None),
            actor_id: r.try_get("actor_id").unwrap_or(None),
            status: r.try_get("status").unwrap_or(None),
            workflow_type: r.try_get("workflow_type").unwrap_or(None),
            timeout_seconds: r.try_get("timeout_seconds").unwrap_or(None),
            input_schema: r.try_get("input_schema").unwrap_or(None),
        }))
    }

    /// Fetch `graph_json` for `workflow_id` scoped to `user_id`. Returns
    /// `Ok(None)` when the workflow does not exist or is not visible.
    ///
    /// The `::text` cast is a no-op today (`workflows.graph_json` is TEXT
    /// in the migration) but is kept for consistency with
    /// [`get_workflow_graph_unchecked`](Self::get_workflow_graph_unchecked)
    /// and [`get_workflow_graphs`](Self::get_workflow_graphs); if the
    /// column is ever migrated to JSONB, all three paths continue to
    /// decode into `String` the same way.
    pub async fn get_workflow_graph(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT graph_json::text FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(workflow_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;

        Ok(row.map(|(gj,)| gj))
    }

    /// Batch variant of [`get_workflow_graph`] — fetches `graph_json` for
    /// every id in `ids` that belongs to `user_id`, in a single query.
    ///
    /// Ids that do not resolve (wrong user or missing workflow) are
    /// simply absent from the returned map. The query projects
    /// `graph_json::text` so JSONB columns are returned as strings, not
    /// parsed `Value`s, matching the caller's expectations.
    pub async fn get_workflow_graphs(
        &self,
        ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<HashMap<Uuid, String>> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, graph_json::text FROM workflows \
             WHERE id = ANY($1) AND user_id = $2",
        )
        .bind(ids)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows.into_iter().collect())
    }

    /// Fetch `(name, graph_json)` for `workflow_id` scoped to `user_id`.
    /// Used by callers that need to display a workflow's name alongside its
    /// graph (e.g. the rotate-secret verification path that test-runs each
    /// dependent workflow and reports results by name).
    pub async fn get_workflow_name_and_graph(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(String, String)>> {
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT name, graph_json::text FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row)
    }

    /// Fetch graph_json without ownership check (used by graph mutation handlers
    /// that have already verified ownership earlier in the call, e.g. system-node builders).
    pub async fn get_workflow_graph_unchecked(&self, workflow_id: Uuid) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT graph_json::text FROM workflows WHERE id = $1")
                .bind(workflow_id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(row.map(|(gj,)| gj))
    }

    /// Fetch the actor_id for a workflow — used at authoring time to enforce capability ceilings.
    /// Returns `Ok(None)` when the workflow has no actor_id or the workflow does not belong
    /// to `user_id`. Returns `Err` only on a real database failure.
    pub async fn get_workflow_actor_id(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Uuid>> {
        let actor_id: Option<Option<Uuid>> =
            sqlx::query_scalar("SELECT actor_id FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(workflow_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(actor_id.flatten())
    }

    /// Fetch the active version's graph_json and version id. Falls back to the draft if no
    /// active version exists. Returns None if the workflow is not found.
    pub async fn get_active_version_graph(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(String, Option<Uuid>)>> {
        // Try active published version first. Scoped by user_id via JOIN on
        // workflows so the SQL itself enforces ownership — defense in depth
        // even if an upstream caller forgets to verify. Without this, a
        // future refactor that loads the active version by workflow_id alone
        // could silently expose another user's published graph.
        let version_row: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT v.id, v.graph_json::text \
             FROM workflow_versions v \
             JOIN workflows w ON w.id = v.workflow_id \
             WHERE v.workflow_id = $1 AND v.is_active = true AND w.user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        if let Some((vid, gj)) = version_row {
            return Ok(Some((gj, Some(vid))));
        }

        // Fall back to draft.
        let draft: Option<(String,)> =
            sqlx::query_as("SELECT graph_json FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(workflow_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;

        Ok(draft.map(|(gj,)| (gj, None)))
    }

    /// Check whether a workflow name is already taken for a user (ignoring archived).
    pub async fn find_workflow_by_name(&self, user_id: Uuid, name: &str) -> Result<Option<Uuid>> {
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM workflows \
             WHERE user_id = $1 AND name = $2 \
             AND (status IS NULL OR status != 'archived') \
             LIMIT 1",
        )
        .bind(user_id)
        .bind(name)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(id)
    }

    /// Fetch the declared input_schema for a workflow. Returns None if not set.
    pub async fn get_workflow_input_schema(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<serde_json::Value>> {
        let schema: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT input_schema FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(workflow_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?
                .flatten();
        Ok(schema)
    }

    // ── Mutation ───────────────────────────────────────────────────────────

    /// Insert a new workflow row. Returns the new workflow's UUID.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_workflow(
        &self,
        user_id: Uuid,
        name: &str,
        graph_json: &str,
        description: Option<&str>,
        tags: &[String],
        capabilities: &[String],
        intent: Option<&serde_json::Value>,
        max_concurrent: Option<i32>,
        timeout_secs: Option<i32>,
        actor_id: Option<Uuid>,
    ) -> Result<Uuid> {
        let wf_id = Uuid::new_v4();
        sqlx::query(
            // RFC 0004: stamp org_id = the creator's personal org (this
            // path has no org-context selector). NULL-tolerant: if the
            // personal org is somehow absent, org_id stays NULL and the
            // owner still sees the row via the user_id union clause.
            "INSERT INTO workflows \
             (id, user_id, name, module_uri, graph_json, description, tags, capabilities, \
              intent, max_concurrent_executions, timeout_seconds, actor_id, readiness_score, \
              created_at, updated_at, org_id) \
             VALUES ($1, $2, $3, '', $4, $5, $6, $7, $8, $9, $10, $11, 0, NOW(), NOW(), \
              (SELECT id FROM organizations WHERE owner_id = $2 AND is_personal))",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(name)
        .bind(graph_json)
        .bind(description)
        .bind(tags)
        .bind(capabilities)
        .bind(intent)
        .bind(max_concurrent)
        .bind(timeout_secs)
        .bind(actor_id)
        .execute(&self.db_pool)
        .await?;
        Ok(wf_id)
    }

    /// Update only graph_json (and bump updated_at). Returns true if a row was affected.
    pub async fn update_workflow_graph(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        graph_json: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE workflows SET graph_json = $1, updated_at = NOW() \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(graph_json)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Update graph_json without the user_id ownership check (used by graph mutation handlers
    /// that have already verified ownership earlier in the call).
    pub async fn update_workflow_graph_unchecked(
        &self,
        workflow_id: Uuid,
        graph_json: &str,
    ) -> Result<bool> {
        let result =
            sqlx::query("UPDATE workflows SET graph_json = $1, updated_at = NOW() WHERE id = $2")
                .bind(graph_json)
                .bind(workflow_id)
                .execute(&self.db_pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Update workflow metadata fields selectively. Returns true if a row was affected.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_workflow_metadata(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        name: Option<&str>,
        description: Option<&str>,
        tags: Option<&[String]>,
        capabilities: Option<&[String]>,
        intent: Option<&serde_json::Value>,
        max_concurrent: Option<i32>,
    ) -> Result<bool> {
        // Build a dynamic SET clause. We always touch updated_at.
        // param_count tracks the number of bound parameters ($1, $2, ...) separately
        // from set_parts.len() because set_parts[0] is "updated_at = NOW()" which
        // has no corresponding bind parameter — mixing the two caused a $N off-by-one
        // that made PostgreSQL see more parameter slots than sqlx actually binds.
        let mut set_parts: Vec<String> = vec!["updated_at = NOW()".to_string()];
        let mut param_count = 0usize;
        if name.is_some() {
            param_count += 1;
            set_parts.push(format!("name = ${}", param_count));
        }
        if description.is_some() {
            param_count += 1;
            set_parts.push(format!("description = ${}", param_count));
        }
        if tags.is_some() {
            param_count += 1;
            set_parts.push(format!("tags = ${}", param_count));
        }
        if capabilities.is_some() {
            param_count += 1;
            set_parts.push(format!("capabilities = ${}", param_count));
        }
        if intent.is_some() {
            param_count += 1;
            set_parts.push(format!("intent = ${}", param_count));
        }
        if max_concurrent.is_some() {
            param_count += 1;
            set_parts.push(format!("max_concurrent_executions = ${}", param_count));
        }

        let where_id_pos = param_count + 1;
        let where_uid_pos = param_count + 2;

        let sql = format!(
            "UPDATE workflows SET {} WHERE id = ${} AND user_id = ${}",
            set_parts.join(", "),
            where_id_pos,
            where_uid_pos
        );

        let mut q = sqlx::query(&sql);
        if let Some(n) = name {
            q = q.bind(n);
        }
        if let Some(d) = description {
            q = q.bind(d);
        }
        if let Some(t) = tags {
            q = q.bind(t);
        }
        if let Some(c) = capabilities {
            q = q.bind(c);
        }
        if let Some(i) = intent {
            q = q.bind(i);
        }
        if let Some(m) = max_concurrent {
            q = q.bind(m);
        }
        q = q.bind(workflow_id).bind(user_id);

        let result = q.execute(&self.db_pool).await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete workflows by ID list (ownership checked). Skips any that have running executions.
    /// Returns `(deleted_ids, blocked_ids)`.
    /// `blocked_ids` — workflows that exist, are owned by user, but have running/queued
    ///   executions preventing deletion.
    /// Ids that don't exist or belong to another user appear in neither list; callers
    /// compute `not_found = requested - deleted - blocked`.
    pub async fn delete_workflows(
        &self,
        ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<(Vec<Uuid>, Vec<Uuid>)> {
        if ids.is_empty() {
            return Ok((vec![], vec![]));
        }
        let deleted_ids: Vec<Uuid> = sqlx::query_scalar(
            "DELETE FROM workflows WHERE id = ANY($1) AND user_id = $2 \
             AND NOT EXISTS ( \
                 SELECT 1 FROM workflow_executions \
                 WHERE workflow_id = workflows.id AND status IN ('running', 'queued', 'pending') \
             ) \
             RETURNING id",
        )
        .bind(ids)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;

        // Only include ids in `blocked` when the workflow EXISTS and is owned by
        // this user but has active executions preventing deletion.  Ids that don't
        // exist (or belong to another user) must NOT appear in `blocked` — the
        // handler uses blocked.is_empty() to distinguish "blocked" from "not found".
        let blocked: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM workflows WHERE id = ANY($1) AND user_id = $2 \
             AND EXISTS ( \
                 SELECT 1 FROM workflow_executions \
                 WHERE workflow_id = workflows.id AND status IN ('running', 'queued', 'pending') \
             )",
        )
        .bind(ids)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await
        .unwrap_or_default();

        Ok((deleted_ids, blocked))
    }

    /// Enable or disable a workflow. Returns true if a row was affected.
    pub async fn set_workflow_enabled(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        enabled: bool,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE workflows SET is_enabled = $1, updated_at = NOW() \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(enabled)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Update the full-text search vector for a workflow (best-effort).
    pub async fn update_workflow_search_text(&self, workflow_id: Uuid, text: &str) -> Result<()> {
        sqlx::query("UPDATE workflows SET search_text = to_tsvector('english', $1) WHERE id = $2")
            .bind(text)
            .bind(workflow_id)
            .execute(&self.db_pool)
            .await?;
        Ok(())
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
             WHERE workflow_id = $1 AND status IN ('running', 'queued', 'pending')",
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
                 WHERE workflow_id = $1 AND status IN ('running', 'queued', 'pending')",
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
    /// (`status IN ('running','queued','pending')`) counts queued rows,
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
                 WHERE workflow_id = $1 AND status IN ('running', 'queued', 'pending')",
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
                 WHERE id = $4 AND status = 'running'",
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
                 WHERE id = $2 AND status = 'running'",
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
                 WHERE id = $4 AND status = 'running'",
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
                 WHERE id = $2 AND status = 'running'",
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
        let output: Option<&serde_json::Value> =
            bounded_output.as_ref().map(|c| c.as_ref());
        // Optional encryption: only encrypt if SM is wired AND we have output.
        let encrypted = match (self.secrets_manager.as_ref(), output) {
            (Some(_), Some(out)) => {
                self.maybe_encrypt_execution_output(execution_id, out).await?
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
                 WHERE id = $5 AND status = 'running'",
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
            let redacted_output =
                output.map(talos_dlp_provider::redact_json);
            sqlx::query(
                "UPDATE workflow_executions \
                 SET status = 'failed', error_message = $1, output_data = $2, \
                     output_data_enc = NULL, output_enc_key_id = NULL, \
                     completed_at = NOW() \
                 WHERE id = $3 AND status = 'running'",
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
        let output: Option<&serde_json::Value> =
            bounded_output.as_ref().map(|c| c.as_ref());
        let encrypted = match (self.secrets_manager.as_ref(), output) {
            (Some(_), Some(out)) => {
                self.maybe_encrypt_execution_output(execution_id, out).await?
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
                 WHERE id = $6 AND status = 'running'",
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
            let redacted_output = output.map(talos_dlp_provider::redact_json);
            sqlx::query(
                "UPDATE workflow_executions \
                 SET status = $1, output_data = $2, \
                     output_data_enc = NULL, output_enc_key_id = NULL, \
                     error_message = $3, completed_at = NOW() \
                 WHERE id = $4 AND status = 'running'",
            )
            .bind(status)
            .bind(redacted_output.as_ref())
            .bind(redacted_error.as_deref())
            .bind(execution_id)
            .execute(&self.db_pool)
            .await?;
        }
        Ok(())
    }

    // ── Module / capability ────────────────────────────────────────────────

    /// Batch-fetch the capability_world for a set of module IDs.
    /// Phase 5.1: queries the unified `modules` table by canonical id.
    pub async fn get_module_capability_worlds(
        &self,
        module_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, String>> {
        if module_ids.is_empty() {
            return Ok(HashMap::new());
        }
        // Project the input id back as the key so callers can lookup by
        let rows: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT id, capability_world FROM modules WHERE id = ANY($1)")
                .bind(module_ids)
                .fetch_all(&self.db_pool)
                .await?;

        // Dedupe — multiple aliases to the same modules row may match the
        // same input_id; HashMap collapses them.
        Ok(rows.into_iter().collect())
    }

    /// Batch-fetch display names for a set of module IDs.
    /// Phase 3.2: queries the unified `modules` table.
    pub async fn get_module_names(&self, module_ids: &[Uuid]) -> Result<HashMap<Uuid, String>> {
        if module_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT id, name FROM modules WHERE id = ANY($1)")
                .bind(module_ids)
                .fetch_all(&self.db_pool)
                .await?;

        Ok(rows.into_iter().collect())
    }

    /// Return the subset of module_ids that are resolvable at execution time.
    ///
    /// Phase 5.1: single SELECT against unified modules table by canonical id.
    pub async fn modules_exist(&self, module_ids: &[Uuid]) -> Result<Vec<Uuid>> {
        if module_ids.is_empty() {
            return Ok(vec![]);
        }
        let rows: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM modules WHERE id = ANY($1)")
            .bind(module_ids)
            .fetch_all(&self.db_pool)
            .await?;

        Ok(rows)
    }

    // ── Actor / budget policy ──────────────────────────────────────────────

    /// Fetch an actor record with its budget policy. Returns None if not found / wrong owner.
    pub async fn get_actor(&self, actor_id: Uuid, user_id: Uuid) -> Result<Option<ActorRow>> {
        let row = sqlx::query(
            "SELECT a.id, a.name, a.status, \
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

        Ok(row.map(|r| ActorRow {
            id: r.get("id"),
            name: r.get("name"),
            status: r.get("status"),
            max_workflow_count: r.try_get("max_workflow_count").unwrap_or(None),
            max_executions_per_hour: r.try_get("max_executions_per_hour").unwrap_or(None),
            max_executions_total: r.try_get("max_executions_total").unwrap_or(None),
        }))
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

    // ── Actor memory (actor_memory table with memory_type) ─────────────────

    /// Fetch recent working/episodic memories for an actor (for context injection).
    pub async fn get_recent_actor_context(
        &self,
        actor_id: Uuid,
    ) -> Result<Vec<(String, serde_json::Value, String)>> {
        talos_memory::recall_recent_by_types(
            &self.db_pool,
            actor_id,
            &["working", "episodic"],
            10,
        )
        .await
    }

    /// Fetch relevant actor memories + graph context for injection.
    ///
    /// Three-layer retrieval:
    /// 1. **Graph RAG**: if Neo4j is connected and context_hint is provided,
    ///    traverse the knowledge graph to find related entities (people,
    ///    tickets, projects) and include them as structured context.
    /// 2. **Vector similarity**: embed the context_hint and find the most
    ///    semantically similar memories via pgvector cosine distance.
    /// 3. **Recency fallback**: if no embeddings or hint, return the most
    ///    recently updated memories across all types.
    ///
    /// The graph context is prepended as a special `__graph_context__`
    /// entry so the LLM sees entity relationships alongside memory values.
    pub async fn get_relevant_actor_context(
        &self,
        actor_id: Uuid,
        limit: usize,
        context_hint: Option<&str>,
    ) -> Result<Vec<(String, serde_json::Value, String)>> {
        let mut results: Vec<(String, serde_json::Value, String)> = Vec::new();

        // Layer 1: Graph RAG — traverse entity relationships.
        if let Some(hint) = context_hint {
            if let Some(graph) = talos_graph_rag::GRAPH_SERVICE.get() {
                match graph.get_graph_context(actor_id, hint, 2, 20).await {
                    Ok(ctx) => {
                        let entity_count = ctx
                            .get("entity_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        if entity_count > 0 {
                            results.push((
                                "__graph_context__".to_string(),
                                ctx,
                                "graph".to_string(),
                            ));
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "Graph context retrieval failed (non-fatal)");
                    }
                }
            }
        }

        // Layer 2: Vector similarity from pgvector.
        let vector_limit = if results.is_empty() {
            limit
        } else {
            limit.saturating_sub(1) // Reserve 1 slot for graph context
        };

        if let Some(hint) = context_hint {
            // Overfetch by 2x so we still hit `vector_limit` distinct
            // non-scratchpad neighbors after the filter below. Without the
            // pad, an actor with mostly engine-trace memories would see its
            // semantic context starved and fall through to Layer 3 every run.
            let vector_fetch_limit = vector_limit.saturating_mul(2).max(vector_limit + 5);
            let outcome = talos_memory::recall_semantic(
                &self.db_pool,
                actor_id,
                hint,
                vector_fetch_limit as i64,
                0.0,
                None,
                talos_memory::SearchMethod::Direct,
            )
            .await?;
            if outcome.method == "vector_cosine" && !outcome.hits.is_empty() {
                // Drop scratchpad engine-trace rows — they're per-execution
                // bookkeeping (key prefix `execution/<id>/trace`, type
                // `scratchpad`) whose JSON value embeds the previous run's
                // `__trigger_input__` which itself embeds `__actor_context__`.
                // Including them would make context injection grow recursively
                // by the entire prior call tree on every run, blowing fuel
                // budgets within a few iterations.
                let filtered: Vec<_> = outcome
                    .hits
                    .into_iter()
                    .filter(|h| h.memory_type != "scratchpad")
                    .take(vector_limit)
                    .map(|h| (h.key, h.value, h.memory_type))
                    .collect();
                if !filtered.is_empty() {
                    results.extend(filtered);
                    return Ok(results);
                }
                // All vector hits were scratchpad — fall through to Layer 3.
            }
        }

        // Layer 3: Recency fallback across non-scratchpad types. The
        // scratchpad exclusion mirrors Layer 2 — see comment above for
        // the recursive-context-growth rationale.
        let extra = talos_memory::recall_recent_excluding_types(
            &self.db_pool,
            actor_id,
            &["scratchpad"],
            limit as i64,
        )
        .await?;
        results.extend(extra);
        Ok(results)
    }

    /// Fetch recent working/episodic memories for an actor with a configurable limit.
    /// (Legacy — callers should prefer get_relevant_actor_context.)
    pub async fn get_recent_actor_context_limited(
        &self,
        actor_id: Uuid,
        limit: usize,
    ) -> Result<Vec<(String, serde_json::Value, String)>> {
        self.get_relevant_actor_context(actor_id, limit, None).await
    }

    /// Upsert a scratchpad execution trace. Delegates to the canonical
    /// memory service so scratchpad writes obey the same TTL and
    /// (non-)embedding rules as every other code path.
    pub async fn upsert_scratchpad_trace(
        &self,
        actor_id: Uuid,
        key: &str,
        value: &serde_json::Value,
    ) -> Result<()> {
        talos_memory::persist_memory(&self.db_pool, actor_id, key, value, "scratchpad", None)
            .await?;
        Ok(())
    }

    // ── Workflow cleanup & archiving ──────────────────────────────────────

    /// Delete all workflows for a user, optionally filtered by name prefix.
    /// Returns the number of rows deleted.
    ///
    /// MCP-719 (2026-05-13): added `ESCAPE '\\'` and inline LIKE-escape
    /// on the prefix so a caller-supplied `%` / `_` is matched literally
    /// instead of as a wildcard. Pre-fix a forgotten escape at the
    /// caller (or a deliberately-malformed prefix like `"%"`) would
    /// DELETE every workflow for the user, since `LIKE '%%'` matches
    /// everything. The user-scope (`WHERE user_id = $1`) keeps the
    /// blast radius bounded to the caller's own data, but
    /// "accidentally nuke all my workflows" is a footgun worth closing
    /// at the repo level rather than relying on every caller to
    /// escape. The function body mirrors
    /// `talos_search_service::escape_like` (cannot import directly —
    /// search-service depends on this crate, so taking the reverse
    /// edge would cycle); replacement order matters (backslash MUST be
    /// doubled first so the `%` / `_` escapes don't get re-doubled).
    pub async fn cleanup_workflows(&self, user_id: Uuid, prefix: Option<&str>) -> Result<u64> {
        let result = if let Some(pfx) = prefix {
            let escaped: String = pfx
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            sqlx::query(
                "DELETE FROM workflows WHERE user_id = $1 AND name LIKE $2 ESCAPE '\\'",
            )
            .bind(user_id)
            .bind(format!("{}%", escaped))
            .execute(&self.db_pool)
            .await?
        } else {
            sqlx::query("DELETE FROM workflows WHERE user_id = $1")
                .bind(user_id)
                .execute(&self.db_pool)
                .await?
        };
        Ok(result.rows_affected())
    }

    /// Find non-archived workflows whose names match a LIKE pattern.
    /// Returns `(id, name)` pairs. Capped at 500 results.
    pub async fn find_workflows_by_prefix(
        &self,
        user_id: Uuid,
        like_pattern: &str,
    ) -> Result<Vec<(Uuid, String)>> {
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, name FROM workflows \
             WHERE user_id = $1 AND name LIKE $2 ESCAPE '\\' \
               AND (status IS NULL OR status != 'archived') \
             ORDER BY name LIMIT 500",
        )
        .bind(user_id)
        .bind(like_pattern)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    /// Archive a set of workflows by ID, optionally stamping a workflow_type.
    /// Returns the number of rows updated.
    pub async fn archive_workflows_by_ids(
        &self,
        ids: &[Uuid],
        user_id: Uuid,
        wf_type: Option<&str>,
    ) -> Result<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        let result = if let Some(t) = wf_type {
            sqlx::query(
                "UPDATE workflows SET status = 'archived', workflow_type = $3, updated_at = NOW() \
                 WHERE id = ANY($1) AND user_id = $2 \
                   AND (status IS NULL OR status != 'archived')",
            )
            .bind(ids)
            .bind(user_id)
            .bind(t)
            .execute(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                "UPDATE workflows SET status = 'archived', updated_at = NOW() \
                 WHERE id = ANY($1) AND user_id = $2 \
                   AND (status IS NULL OR status != 'archived')",
            )
            .bind(ids)
            .bind(user_id)
            .execute(&self.db_pool)
            .await?
        };
        Ok(result.rows_affected())
    }

    // ── Simple single-field workflow updates ──────────────────────────────

    /// Set the input_schema for a workflow. Returns true if a row was updated.
    pub async fn set_workflow_input_schema(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        schema: &serde_json::Value,
    ) -> Result<bool> {
        let result =
            sqlx::query("UPDATE workflows SET input_schema = $1 WHERE id = $2 AND user_id = $3")
                .bind(schema)
                .bind(workflow_id)
                .bind(user_id)
                .execute(&self.db_pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Set the workflow_type column. Returns true if a row was updated.
    pub async fn set_workflow_type(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        wf_type: &str,
    ) -> Result<bool> {
        let result =
            sqlx::query("UPDATE workflows SET workflow_type = $1 WHERE id = $2 AND user_id = $3")
                .bind(wf_type)
                .bind(workflow_id)
                .bind(user_id)
                .execute(&self.db_pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Update the description of a workflow. Returns true if a row was updated.
    pub async fn set_workflow_description(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        description: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE workflows SET description = $1, updated_at = NOW() \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(description)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Bind or unbind the default actor on a workflow. Returns true if a
    /// row was updated. `actor_id = None` clears the binding (the workflow
    /// becomes "shared mode" — every caller must pass actor_id explicitly,
    /// otherwise __memory_write__ envelopes silently drop).
    ///
    /// Caller MUST pre-validate that:
    ///   1. The workflow is owned by `user_id` (this query enforces that).
    ///   2. When `actor_id` is `Some(_)`, the actor exists, is non-archived,
    ///      and is owned by the same `user_id` (cross-user actor binding
    ///      would let user A's workflow stamp user B's actor on every
    ///      execution — defense in depth lives in the caller per the
    ///      service-layer pattern; this repo method does NOT re-check the
    ///      actor side).
    pub async fn set_workflow_actor_id(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        actor_id: Option<Uuid>,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE workflows SET actor_id = $1, updated_at = NOW() \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(actor_id)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    // ── Execution statistics ───────────────────────────────────────────────

    /// Fetch aggregated execution stats for a workflow over the past N days.
    pub async fn get_workflow_execution_stats(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        days: i32,
    ) -> Result<WorkflowExecStats> {
        // avg_duration_secs is filtered to status='completed' so phantom-
        // duration outliers don't distort it. Stale-cleanup failures
        // (auto-marked failed after the timeout threshold) carry a
        // ~1h `completed_at - started_at`; a single one of these in a
        // 13-execution window pulled daily-brief's reported avg from
        // ~20s to ~300s in production. Keeping the average tied to
        // successful runs makes it usable for capacity planning;
        // operators who want failure-cost data should look at the
        // failed-execution log.
        let row = sqlx::query(
            "SELECT \
                COUNT(*)::bigint AS total, \
                COUNT(*) FILTER (WHERE status = 'completed')::bigint AS succeeded, \
                COUNT(*) FILTER (WHERE status = 'failed')::bigint AS failed, \
                COUNT(*) FILTER (WHERE status = 'running')::bigint AS running, \
                (AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) \
                    FILTER (WHERE completed_at IS NOT NULL AND status = 'completed'))::float8 AS avg_duration_secs \
             FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 \
               AND started_at > NOW() - make_interval(days => $3)",
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(days)
        .fetch_one(&self.db_pool)
        .await?;

        Ok(WorkflowExecStats {
            total: row.try_get("total").unwrap_or(0),
            succeeded: row.try_get("succeeded").unwrap_or(0),
            failed: row.try_get("failed").unwrap_or(0),
            running: row.try_get("running").unwrap_or(0),
            avg_duration_secs: row.try_get("avg_duration_secs").unwrap_or(None),
        })
    }

    /// Batch sibling to [`get_workflow_execution_stats`]. Single
    /// `WHERE workflow_id = ANY($1) AND user_id = $2 GROUP BY workflow_id`
    /// query replaces the per-id loop used by the workflow-health handler
    /// when reporting on sub-workflow stats.
    ///
    /// Workflows with zero executions in the window simply don't appear
    /// in the result map — callers should `.get(id).copied()
    /// .unwrap_or_default()` (the empty stats shape). Empty input
    /// short-circuits without touching the DB.
    ///
    /// Security: same `AND user_id = $2` scoping as the per-id method.
    pub async fn get_workflow_execution_stats_for_ids(
        &self,
        workflow_ids: &[Uuid],
        user_id: Uuid,
        days: i32,
    ) -> Result<std::collections::HashMap<Uuid, WorkflowExecStats>> {
        if workflow_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        // See `get_workflow_execution_stats` for the rationale on the
        // status='completed' AVG filter — same intent here.
        let rows = sqlx::query(
            "SELECT workflow_id, \
                    COUNT(*)::bigint AS total, \
                    COUNT(*) FILTER (WHERE status = 'completed')::bigint AS succeeded, \
                    COUNT(*) FILTER (WHERE status = 'failed')::bigint AS failed, \
                    COUNT(*) FILTER (WHERE status = 'running')::bigint AS running, \
                    (AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) \
                        FILTER (WHERE completed_at IS NOT NULL AND status = 'completed'))::float8 AS avg_duration_secs \
             FROM workflow_executions \
             WHERE workflow_id = ANY($1) AND user_id = $2 \
               AND started_at > NOW() - make_interval(days => $3) \
             GROUP BY workflow_id",
        )
        .bind(workflow_ids)
        .bind(user_id)
        .bind(days)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let id: Uuid = row.try_get("workflow_id").unwrap_or_default();
                let stats = WorkflowExecStats {
                    total: row.try_get("total").unwrap_or(0),
                    succeeded: row.try_get("succeeded").unwrap_or(0),
                    failed: row.try_get("failed").unwrap_or(0),
                    running: row.try_get("running").unwrap_or(0),
                    avg_duration_secs: row.try_get("avg_duration_secs").unwrap_or(None),
                };
                (id, stats)
            })
            .collect())
    }

    /// Batch fetch of `(workflow_id, name)` pairs scoped to `user_id`.
    /// Used by the workflow-health handler to resolve sub-workflow names
    /// without paying for a full `get_workflow` round-trip per child.
    /// Workflows the caller doesn't own are excluded from the result;
    /// callers reading "does this id resolve" should use `.contains_key`.
    /// Empty input short-circuits without touching the DB.
    pub async fn get_workflow_names_by_ids(
        &self,
        workflow_ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<std::collections::HashMap<Uuid, String>> {
        if workflow_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rows: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT id, name FROM workflows WHERE id = ANY($1) AND user_id = $2")
                .bind(workflow_ids)
                .bind(user_id)
                .fetch_all(&self.db_pool)
                .await?;
        Ok(rows.into_iter().collect())
    }

    /// Fetch version metadata for a workflow (count, latest version number, last published).
    pub async fn get_workflow_version_info(
        &self,
        workflow_id: Uuid,
    ) -> Result<WorkflowVersionInfo> {
        let row = sqlx::query(
            "SELECT COUNT(*)::bigint AS total_versions, \
                    MAX(version_number) AS latest_version, \
                    MAX(published_at) AS last_published \
             FROM workflow_versions WHERE workflow_id = $1",
        )
        .bind(workflow_id)
        .fetch_one(&self.db_pool)
        .await?;

        Ok(WorkflowVersionInfo {
            total_versions: row.try_get("total_versions").unwrap_or(0),
            latest_version: row.try_get("latest_version").unwrap_or(None),
            last_published: row.try_get("last_published").unwrap_or(None),
        })
    }

    /// Count active schedules for a workflow.
    pub async fn get_workflow_schedule_count(&self, workflow_id: Uuid) -> Result<i64> {
        // The `workflow_schedules` table column is `is_enabled` (per
        // migration 20260309000200), NOT `is_active`. Pre-fix this
        // query referenced the non-existent column; handler
        // `unwrap_or(0)` swallowed the column-not-found error and
        // `get_workflow_summary` reported `active_schedules: 0` for
        // every workflow, including ones with active schedules. Same
        // class as the get_schedule_health zeros bug — discovered via
        // MCP probe 2026-05-06 (daily-brief shows is_enabled=true in
        // list_schedules but active_schedules=0 in summary).
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM workflow_schedules \
             WHERE workflow_id = $1 AND is_enabled = true",
        )
        .bind(workflow_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    /// Count active webhook triggers for a set of module IDs owned by a user.
    pub async fn get_workflow_webhook_count(
        &self,
        module_ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<i64> {
        if module_ids.is_empty() {
            return Ok(0);
        }
        // webhook_triggers column is `enabled` (initial schema +
        // never renamed). Same column-drift class as
        // get_workflow_schedule_count — pre-fix this query
        // referenced `is_active`, errored at runtime, and the
        // caller's unwrap_or(0) silently reported "0 active webhooks"
        // in get_workflow_summary.
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM webhook_triggers \
             WHERE module_id = ANY($1) AND enabled = true AND user_id = $2",
        )
        .bind(module_ids)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    // ── Node template helpers ─────────────────────────────────────────────

    // MCP-957 (2026-05-15): deleted dead `find_template_by_name(name)`
    // — unscoped `SELECT id FROM modules WHERE name = $1` with zero
    // call sites; same cross-tenant module-ID leak class as MCP-956
    // had it ever been used. Canonical scoped lookups live in
    // `ModuleRepository::find_template_id_by_name_ci(name, user_id)`.

    /// Find a node template that also has a compiled wasm payload
    /// (catalog templates compile once and are shared; user-private
    /// templates compile per owner).
    ///
    /// MCP-957 (2026-05-15): scoped by user. Pre-fix the SELECT was
    /// unscoped — `instantiate_workflow_pattern` would resolve a
    /// pattern's `module_name` against ANY tenant's compiled module
    /// row, producing a workflow whose `module_id` pointed at the
    /// foreign tenant's UUID. Downstream load would fail (the
    /// owning-user check on read denies cross-tenant access) but the
    /// failure mode was confusing and the cross-tenant UUID-by-name
    /// disclosure was a real info leak. Sibling-class fix to MCP-956
    /// on the workflow-repo side.
    ///
    /// Used by `instantiate_workflow_pattern` to avoid the class of bug
    /// where the resolver reports `missing_modules: []` because the
    /// name exists in `modules`, but the engine then fails at
    /// execution time because no `wasm_bytes` carries the
    /// compiled payload for that template. Returns `None` for templates
    /// that exist but haven't been compiled — callers should treat
    /// these as missing and surface them so users install or compile
    /// the module before instantiation.
    pub async fn find_compiled_template_by_name(
        &self,
        name: &str,
        user_id: Uuid,
    ) -> Result<Option<Uuid>> {
        // Phase 5.1: query the unified `modules` table. Compiled-ness is
        // signalled by a non-empty `wasm_bytes` column. Returns canonical id.
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id \
               FROM modules \
              WHERE name = $1 \
                AND wasm_bytes IS NOT NULL AND octet_length(wasm_bytes) > 0 \
                AND (user_id IS NULL OR user_id = $2) \
              LIMIT 1",
        )
        .bind(name)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(id)
    }

    /// Batch-fetch the *installed* allowed_secrets for a set of template IDs.
    ///
    /// Phase 5: queries the unified `modules` table. When multiple rows resolve
    /// under the same input id (e.g. different content_hash after source
    /// change), the most recent compiled_at wins. Returns a map keyed by the
    /// input id shape (callers index by what they passed in).
    pub async fn get_installed_secrets_by_template_ids(
        &self,
        template_ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<std::collections::HashMap<Uuid, Vec<String>>> {
        if template_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rows = sqlx::query(
            "SELECT id AS template_id, allowed_secrets FROM modules \
             WHERE id = ANY($1) AND user_id = $2 \
             ORDER BY id, compiled_at DESC NULLS LAST",
        )
        .bind(template_ids)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|r| {
                let tid: Uuid = r.try_get("template_id").ok()?;
                let secrets: Vec<String> = decode_allowed_secrets_row(&r, Some(tid));
                Some((tid, secrets))
            })
            .collect())
    }

    /// Batch-fetch node template metadata (name, config_schema, allowed_secrets).
    /// Phase 5.1: queries the unified modules table by canonical id.
    pub async fn get_templates_by_ids(&self, ids: &[Uuid]) -> Result<Vec<NodeTemplateRow>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let rows = sqlx::query(
            "SELECT id, name, config_schema, allowed_secrets, max_retries \
             FROM modules \
             WHERE id = ANY($1)",
        )
        .bind(ids)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let id: Uuid = r.get("id");
                NodeTemplateRow {
                    id,
                    name: r.get("name"),
                    config_schema: r.try_get("config_schema").unwrap_or(serde_json::json!({})),
                    allowed_secrets: decode_allowed_secrets_row(&r, Some(id)),
                    max_retries: r.try_get("max_retries").unwrap_or(0),
                }
            })
            .collect())
    }

    /// Find a module by display name (case-insensitive) — for swap_node_module.
    ///
    /// Phase 5.1: queries the unified `modules` table by canonical id.
    /// Prefers the caller's user-installed instance over the system-seeded
    /// catalog row when both exist. Without this preference the swap would
    /// land on `user_id IS NULL` rows the caller can't `hot_update_module`,
    /// so fuel/config tuning would silently fail post-swap.
    pub async fn find_template_by_display_name(
        &self,
        display_name: &str,
        user_id: Uuid,
    ) -> Result<Option<NodeTemplateRow>> {
        let row = sqlx::query(
            "SELECT id, name, config_schema, \
                    allowed_secrets, max_retries \
             FROM modules \
             WHERE LOWER(name) = LOWER($1) \
               AND (user_id = $2 OR user_id IS NULL) \
             ORDER BY (user_id IS NOT NULL) DESC, created_at DESC \
             LIMIT 1",
        )
        .bind(display_name)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(row.map(|r| {
            let id: Uuid = r.get("id");
            NodeTemplateRow {
                id,
                name: r.get("name"),
                config_schema: r.try_get("config_schema").unwrap_or(serde_json::json!({})),
                allowed_secrets: decode_allowed_secrets_row(&r, Some(id)),
                max_retries: r.try_get("max_retries").unwrap_or(0),
            }
        }))
    }

    /// Find a node template by name for a specific user (used by inline compilation).
    /// Phase 3.2: queries the unified modules table (kind='extracted' is what
    /// add_node_to_workflow rust_code creates; kind='sandbox' covers
    /// compile_custom_sandbox if that name was reused).
    pub async fn find_node_template_by_name_and_user(
        &self,
        name: &str,
        user_id: Uuid,
    ) -> Result<Option<Uuid>> {
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM modules \
             WHERE name = $1 AND user_id = $2 \
               AND kind IN ('extracted', 'sandbox') \
               AND wasm_bytes IS NOT NULL \
             LIMIT 1",
        )
        .bind(name)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(id)
    }

    /// Fetch the installed permissions + capability_world for an owned module.
    /// Used by the inline-compile path to surface permission drift between a
    /// caller's explicit allowed_hosts / allowed_secrets / allowed_methods and
    /// an existing same-named module's stored values — so the caller isn't
    /// silently saddled with narrower (or broader) permissions than they asked for.
    pub async fn get_module_permissions(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ModulePermissions>> {
        use sqlx::Row;
        let row = sqlx::query(
            "SELECT allowed_hosts, allowed_secrets, allowed_methods, capability_world \
             FROM modules \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.map(|r| ModulePermissions {
            allowed_hosts: r.try_get("allowed_hosts").unwrap_or_default(),
            allowed_secrets: decode_allowed_secrets_row(&r, Some(module_id)),
            allowed_methods: r.try_get("allowed_methods").unwrap_or_default(),
            capability_world: r.try_get("capability_world").unwrap_or_default(),
        }))
    }

    /// Update an existing module's WASM + metadata (inline compilation retry path).
    ///
    /// Phase 5.1: writes directly to the unified `modules` table by canonical id.
    /// `capability_world` is stored in long form (`secrets-node`) on `modules`;
    /// convert from the short form callers pass in.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_node_template_wasm(
        &self,
        id: Uuid,
        wasm_bytes: &[u8],
        code: &str,
        world: &str,
        secrets: &[String],
        hosts: &[String],
        integration_name: Option<&str>,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        let content_hash = format!("{:x}", Sha256::digest(wasm_bytes));
        // Normalise to long form (`secrets-node`) — modules table CHECK expects it.
        let cw_long = if world == "trusted" {
            "automation-node".to_string()
        } else if world.ends_with("-node") {
            world.to_string()
        } else {
            format!("{}-node", world)
        };
        sqlx::query(
            "UPDATE modules \
             SET wasm_bytes = $1, source_code = $2, capability_world = $3, \
                 allowed_secrets = $4, allowed_hosts = $5, \
                 integration_name = $7, content_hash = $8, \
                 size_bytes = $9, compiled_at = NOW(), updated_at = NOW() \
             WHERE id = $6",
        )
        .bind(wasm_bytes)
        .bind(code)
        .bind(cw_long)
        .bind(secrets)
        .bind(hosts)
        .bind(id)
        .bind(integration_name)
        .bind(&content_hash)
        .bind(wasm_bytes.len() as i32)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Insert a new module (inline compilation when name is new).
    ///
    /// Phase 5.1: writes directly to the unified `modules` table with
    /// `kind = 'extracted'` (matches the `add_node_to_workflow` rust_code
    /// path).
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_node_template(
        &self,
        id: Uuid,
        name: &str,
        wasm_bytes: &[u8],
        code: &str,
        world: &str,
        secrets: &[String],
        hosts: &[String],
        user_id: Uuid,
        integration_name: Option<&str>,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        let content_hash = format!("{:x}", Sha256::digest(wasm_bytes));
        // Normalise to long form (`secrets-node`) — modules table CHECK expects it.
        let cw_long = if world == "trusted" {
            "automation-node".to_string()
        } else if world.ends_with("-node") {
            world.to_string()
        } else {
            format!("{}-node", world)
        };
        let empty: Vec<String> = Vec::new();
        sqlx::query(
            "INSERT INTO modules ( \
                id, user_id, name, kind, capability_world, \
                allowed_hosts, allowed_methods, allowed_secrets, \
                source_code, wasm_bytes, content_hash, size_bytes, \
                integration_name, language, \
                created_at, compiled_at, updated_at \
             ) VALUES ( \
                $1, $2, $3, 'extracted', $4, \
                $5, $6, $7, \
                $8, $9, $10, $11, \
                $12, 'rust', \
                NOW(), NOW(), NOW() \
             )",
        )
        .bind(id)
        .bind(user_id)
        .bind(name)
        .bind(cw_long)
        .bind(hosts)
        .bind(&empty)
        .bind(secrets)
        .bind(code)
        .bind(wasm_bytes)
        .bind(&content_hash)
        .bind(wasm_bytes.len() as i32)
        .bind(integration_name)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Returns the (id, name) of every non-archived workflow owned by `user_id`
    /// whose graph references `module_id`, EXCLUDING `current_workflow_id`.
    ///
    /// Used by `add_node_to_workflow` to refuse a silent overwrite when an
    /// inline `node_id` collides with an existing module that other workflows
    /// already depend on. Without this guard, the BUG-25 retry-after-failure
    /// path silently mutates production modules — a correctness + security
    /// hazard since the new code may have a different capability set.
    ///
    /// Capped at 20 for bounded response size; that's enough rows to make
    /// the collision explanation actionable without dumping the full call
    /// graph into the error message.
    pub async fn workflows_using_module_excluding(
        &self,
        module_id: Uuid,
        current_workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<(Uuid, String)>> {
        let pattern = format!("%{}%", module_id);
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, name FROM workflows \
             WHERE user_id = $1 \
               AND id != $2 \
               AND graph_json LIKE $3 \
               AND (status IS NULL OR status != 'archived') \
             ORDER BY updated_at DESC \
             LIMIT 20",
        )
        .bind(user_id)
        .bind(current_workflow_id)
        .bind(&pattern)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    // ── Secrets provisioning ──────────────────────────────────────────────

    /// Return which of the provided secret key-paths are already provisioned.
    pub async fn get_provisioned_secrets(
        &self,
        paths: &[String],
        user_id: Uuid,
    ) -> Result<Vec<String>> {
        if paths.is_empty() {
            return Ok(vec![]);
        }
        // MCP-676 (2026-05-13): canonical owner column is `owner_user_id`,
        // NOT `user_id`. The `user_id` column is a 001_initial_schema
        // leftover never written by any production code path; using it
        // as the ownership predicate returned an empty Vec for every
        // user regardless of secret count. Sibling fix to the
        // controller `/metrics` user-stats endpoint that had the same
        // copy-paste bug. The talos-secrets-manager INSERT path writes
        // BOTH `created_by` AND `owner_user_id` to the creating user
        // (verified at manager.rs:865 — `INSERT INTO secrets (..., created_by,
        // owner_user_id, ...)`).
        let provisioned: Vec<String> = sqlx::query_scalar(
            "SELECT key_path FROM secrets WHERE key_path = ANY($1) AND owner_user_id = $2",
        )
        .bind(paths)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(provisioned)
    }

    // ── Module export ──────────────────────────────────────────────────────

    /// Batch-fetch module metadata for export.
    ///
    /// Phase 5: queries the unified `modules` table with 3-shape id matching.
    /// Preserves the legacy "compiled vs template" split in the `category`
    /// projection so export bundles keep their existing schema: rows with
    /// `wasm_bytes` populated project `category = "compiled"` + `source_code`
    /// (from `modules.source_code`); rows without project the persisted
    /// `category` (from Phase 1.5 column) or fall back to "template" and
    /// expose `code_template` (also from `modules.source_code`, where inline
    /// catalog templates originally lived).
    pub async fn get_module_export_metadata(
        &self,
        module_ids: &[Uuid],
        include_source: bool,
    ) -> Result<Vec<ModuleExportInfo>> {
        if module_ids.is_empty() {
            return Ok(vec![]);
        }

        let rows = sqlx::query(
            "SELECT id AS input_id, name, capability_world, \
                    wasm_bytes IS NOT NULL AND octet_length(wasm_bytes) > 0 AS is_compiled, \
                    category, source_code \
             FROM modules \
             WHERE id = ANY($1) \
             ORDER BY id, (wasm_bytes IS NOT NULL) DESC",
        )
        .bind(module_ids)
        .fetch_all(&self.db_pool)
        .await
        .unwrap_or_default();

        let mut out: Vec<ModuleExportInfo> = Vec::new();
        for r in &rows {
            let id: Uuid = r.get("input_id");
            let is_compiled: bool = r.try_get("is_compiled").unwrap_or(false);
            let name: String = r.get("name");
            let capability_world: Option<String> = r.try_get("capability_world").ok();
            let category_persisted: Option<String> = r.try_get("category").ok();
            let source_code: Option<String> = if include_source {
                r.try_get::<Option<String>, _>("source_code")
                    .unwrap_or(None)
            } else {
                None
            };
            if is_compiled {
                out.push(ModuleExportInfo {
                    id,
                    name,
                    category: category_persisted.unwrap_or_else(|| "compiled".to_string()),
                    capability_world,
                    source_code,
                    code_template: None,
                });
            } else {
                out.push(ModuleExportInfo {
                    id,
                    name,
                    category: category_persisted.unwrap_or_else(|| "template".to_string()),
                    capability_world: None,
                    source_code: None,
                    // `code_template` historically came from
                    // node_templates.code_template, which maps to
                    // `modules.source_code` post-consolidation. Emit it
                    // in the export bundle when requested so existing
                    // importers keep parsing.
                    code_template: if include_source { source_code } else { None },
                });
            }
        }

        Ok(out)
    }

    /// Insert a compiled WASM module from an import bundle. Skips on conflict.
    ///
    /// Phase 5.1: writes directly to the unified `modules` table with
    /// `kind = 'sandbox'` (import bundles represent compile-time artifacts
    /// of user-authored modules; matches `compile_custom_sandbox`'s kind).
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_wasm_module(
        &self,
        id: Uuid,
        user_id: Uuid,
        name: &str,
        wasm_bytes: &[u8],
        source_code: &str,
        capability_world: &str,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        let content_hash = format!("{:x}", Sha256::digest(wasm_bytes));
        // Normalise to long form for the modules table CHECK.
        let cw_long = if capability_world == "trusted" {
            "automation-node".to_string()
        } else if capability_world.ends_with("-node") {
            capability_world.to_string()
        } else {
            format!("{}-node", capability_world)
        };
        let empty: Vec<String> = Vec::new();
        sqlx::query(
            "INSERT INTO modules ( \
                id, user_id, name, kind, capability_world, \
                allowed_hosts, allowed_methods, allowed_secrets, \
                source_code, wasm_bytes, content_hash, size_bytes, \
                language, \
                created_at, compiled_at, updated_at \
             ) VALUES ( \
                $1, $2, $3, 'sandbox', $4, \
                $5, $5, $5, \
                $6, $7, $8, $9, \
                'rust', \
                NOW(), NOW(), NOW() \
             ) ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .bind(user_id)
        .bind(name)
        .bind(cw_long)
        .bind(&empty)
        .bind(source_code)
        .bind(wasm_bytes)
        .bind(&content_hash)
        .bind(wasm_bytes.len() as i32)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// All modules ordered by name — used by LLM scaffolding to build a
    /// compact catalog of available node types.
    ///
    /// Phase 5.1: reads from the unified `modules` table by canonical id.
    /// `is_compiled` is true when `wasm_bytes` is populated. `category`
    /// prefers the persisted Phase 1.5 column, falling back to `kind` so
    /// sandbox / extracted rows still label sensibly.
    pub async fn list_scaffolding_templates(&self) -> Result<Vec<ScaffoldingTemplateRow>> {
        let rows = sqlx::query(
            "SELECT id, name, \
                    COALESCE(category, kind) AS category, description, \
                    (wasm_bytes IS NOT NULL AND octet_length(wasm_bytes) > 0) AS is_compiled \
             FROM modules ORDER BY name",
        )
        .fetch_all(&self.db_pool)
        .await?;

        let result = rows
            .iter()
            .map(|r| ScaffoldingTemplateRow {
                id: r.try_get("id").unwrap_or_default(),
                name: r.try_get("name").unwrap_or_default(),
                category: r.try_get("category").unwrap_or_default(),
                description: r.try_get("description").unwrap_or(None),
                is_compiled: r.try_get("is_compiled").unwrap_or(false),
            })
            .collect();
        Ok(result)
    }

    /// Count active (non-archived) workflows owned by `user_id` whose name
    /// matches `name` but whose id differs from `exclude_id`.  Used to surface
    /// a soft name-collision warning after LLM scaffolding.
    pub async fn count_workflow_name_collision(
        &self,
        user_id: Uuid,
        name: &str,
        exclude_id: Uuid,
    ) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM workflows \
             WHERE user_id = $1 AND name = $2 AND id != $3 \
             AND (status IS NULL OR status != 'archived')",
        )
        .bind(user_id)
        .bind(name)
        .bind(exclude_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional Row DTOs
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct WorkflowExecStats {
    pub total: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub running: i64,
    /// Average wall-clock duration of *successful* runs only — the
    /// underlying SQL filters on `status = 'completed'` so phantom
    /// durations from stale-cleanup failures don't distort capacity-
    /// planning consumers. `None` when no completed runs exist in the
    /// window.
    pub avg_duration_secs: Option<f64>,
}

impl WorkflowExecStats {
    /// Empty stats — handlers use this as the fall-back when the
    /// underlying query fails. Pulled into a constructor so the same
    /// `unwrap_or(...)` literal isn't pasted at every call site (the
    /// previous shape had this exact `{total:0, succeeded:0, ...}` block
    /// duplicated in `get_workflow_health` parent + child branches).
    pub fn empty() -> Self {
        Self {
            total: 0,
            succeeded: 0,
            failed: 0,
            running: 0,
            avg_duration_secs: None,
        }
    }

    /// Compute success rate as a percentage 0.0–100.0; zero if no runs.
    pub fn success_rate_percent(&self) -> f64 {
        if self.total > 0 {
            (self.succeeded as f64 / self.total as f64) * 100.0
        } else {
            0.0
        }
    }

    /// Project to the canonical JSON shape used by `get_workflow_health`
    /// (parent + sub-workflow entries) and `get_workflow_summary`.
    /// Caller supplies `period_days` so the same struct can be projected
    /// against different windows.
    ///
    /// MCP-19 (2026-05-07): success_rate_percent now emits a JSON number
    /// rounded to 1 decimal place. Pre-fix this projection used
    /// `format!("{:.1}", ...)`, while talos-analytics-repository's
    /// `format_percent` helper emits numbers — `get_workflow_health`
    /// kept emitting strings even after the round-4 fix because the
    /// projection lives here, not in the handler. Inlined the rounding
    /// (rather than adding a workspace dep on talos-analytics-repository
    /// for one tiny helper).
    pub fn to_json(&self, period_days: i32) -> serde_json::Value {
        let raw = self.success_rate_percent();
        let success_rate_percent = if raw.is_finite() {
            (raw * 10.0).round() / 10.0
        } else {
            0.0
        };
        // MCP-30 (2026-05-07): cap avg_duration_secs at 2 decimals.
        // Pre-fix the projection emitted the raw f64 from the SQL
        // EXTRACT(EPOCH FROM ...) which gave 6+ digits of precision —
        // operator-readable durations don't need sub-millisecond
        // precision. 2dp matches the existing `compute_units` /
        // `avg_node_time_ms` precision in get_execution_cost.
        let avg_duration_secs = self.avg_duration_secs.map(|v| {
            if v.is_finite() {
                (v * 100.0).round() / 100.0
            } else {
                0.0
            }
        });
        serde_json::json!({
            "period_days": period_days,
            "total_executions": self.total,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "running": self.running,
            "success_rate_percent": success_rate_percent,
            "avg_duration_secs": avg_duration_secs,
        })
    }
}

#[derive(Debug)]
pub struct WorkflowVersionInfo {
    pub total_versions: i64,
    pub latest_version: Option<i32>,
    pub last_published: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug)]
pub struct NodeTemplateRow {
    pub id: Uuid,
    pub name: String,
    pub config_schema: serde_json::Value,
    pub allowed_secrets: Vec<String>,
    /// Default max retries for nodes using this template (0 = no retries).
    /// Applied by add_node_to_workflow when the caller doesn't provide retry_count.
    pub max_retries: i32,
}

/// The four per-module permission columns, fetched together for drift checks.
#[derive(Debug, Clone, Default)]
pub struct ModulePermissions {
    pub allowed_hosts: Vec<String>,
    pub allowed_secrets: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub capability_world: String,
}

#[derive(Debug)]
pub struct ModuleExportInfo {
    pub id: Uuid,
    pub name: String,
    pub category: String,
    pub capability_world: Option<String>,
    pub source_code: Option<String>,
    pub code_template: Option<String>,
}

// ── Semantic execution cache repository methods ──────────────────────────────

impl WorkflowRepository {
    /// Check if a workflow exists and is owned by the given user.
    ///
    /// MCP-876 (2026-05-14): log the underlying sqlx error on failure
    /// before collapsing to `false`. Pre-fix `.unwrap_or(false)`
    /// silently treated DB errors (connection-pool exhausted, query
    /// timeout, FK violation) identically to "row missing or wrong
    /// owner" — fail-closed is correct here (every caller routes
    /// `false` to "Workflow not found"), but operators investigating
    /// a flood of "workflow not found" reports had no signal whether
    /// to look at user mistakes vs DB infrastructure. Now the WARN
    /// log lets the audit team correlate.
    ///
    /// Note: API-shape follow-up worth doing — return `Result<bool>`
    /// so the 10+ MCP callers can distinguish the two outcomes in
    /// their user-facing error messages (separate "we have a DB
    /// issue, retry" path from "this workflow really isn't yours").
    /// Out of scope for this fix; the telemetry below covers the
    /// silent-incident case.
    pub async fn workflow_exists(&self, workflow_id: Uuid, user_id: Uuid) -> bool {
        match sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM workflows WHERE id = $1 AND user_id = $2)",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await
        {
            Ok(exists) => exists,
            Err(e) => {
                tracing::warn!(
                    workflow_id = %workflow_id,
                    user_id = %user_id,
                    error = %e,
                    "workflow_exists query failed — returning false (fail-closed); \
                     callers will surface this as 'Workflow not found' to the user"
                );
                false
            }
        }
    }

    /// Exact hash lookup in the semantic execution cache.
    pub async fn get_exact_cache_hit(
        &self,
        workflow_id: Uuid,
        input_hash: &str,
    ) -> Option<serde_json::Value> {
        sqlx::query_scalar(
            "SELECT output_json FROM semantic_execution_cache \
             WHERE workflow_id = $1 AND input_hash = $2 \
               AND (expires_at IS NULL OR expires_at > now()) \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(workflow_id)
        .bind(input_hash)
        .fetch_optional(&self.db_pool)
        .await
        .ok()
        .flatten()
    }

    /// Increment the hit count for a cache entry (fire-and-forget).
    ///
    /// L T5-1: persistent UPDATE failures used to be discarded via
    /// `let _ = ...`, so a backed-up DB or schema-migration window
    /// silently produced zero increments — operator dashboards would
    /// show "0 cache hits" while the cache was actually serving
    /// heavily. We still spawn (don't block the read path) but log
    /// the error so the outage is visible.
    pub fn increment_cache_hit_count(&self, workflow_id: Uuid, input_hash: String) {
        let pool = self.db_pool.clone();
        tokio::spawn(async move {
            if let Err(e) = sqlx::query(
                "UPDATE semantic_execution_cache SET hit_count = hit_count + 1 \
                 WHERE workflow_id = $1 AND input_hash = $2",
            )
            .bind(workflow_id)
            .bind(&input_hash)
            .execute(&pool)
            .await
            {
                tracing::warn!(
                    target: "talos_workflow_repo",
                    event_kind = "cache_hit_increment_failed",
                    %workflow_id,
                    error = %e,
                    "increment_cache_hit_count: best-effort UPDATE failed"
                );
            }
        });
    }

    /// Semantic similarity lookup in the execution cache using pgvector.
    pub async fn get_semantic_cache_hit(
        &self,
        workflow_id: Uuid,
        embedding_str: &str,
        threshold: f64,
    ) -> Option<(serde_json::Value, f64)> {
        sqlx::query_as(
            "SELECT output_json, (1.0 - (input_embedding <=> $2::vector)) AS score \
             FROM semantic_execution_cache \
             WHERE workflow_id = $1 \
               AND input_embedding IS NOT NULL \
               AND (expires_at IS NULL OR expires_at > now()) \
               AND (1.0 - (input_embedding <=> $2::vector)) >= $3 \
             ORDER BY input_embedding <=> $2::vector \
             LIMIT 1",
        )
        .bind(workflow_id)
        .bind(embedding_str)
        .bind(threshold)
        .fetch_optional(&self.db_pool)
        .await
        .ok()
        .flatten()
    }

    /// Write or update a semantic cache entry. Returns the row ID.
    pub async fn upsert_cache_entry(
        &self,
        workflow_id: Uuid,
        input_hash: &str,
        input: &serde_json::Value,
        output: &serde_json::Value,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Uuid> {
        let id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO semantic_execution_cache \
             (workflow_id, input_hash, input_json, output_json, expires_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (workflow_id, input_hash) DO UPDATE \
               SET output_json = EXCLUDED.output_json, \
                   expires_at  = EXCLUDED.expires_at, \
                   hit_count   = 0 \
             RETURNING id",
        )
        .bind(workflow_id)
        .bind(input_hash)
        .bind(input)
        .bind(output)
        .bind(expires_at)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(id)
    }

    /// Asynchronously update the embedding vector for a cache entry.
    pub fn update_cache_embedding(&self, row_id: Uuid, embedding_str: String) {
        let pool = self.db_pool.clone();
        tokio::spawn(async move {
            if let Err(e) = sqlx::query(
                "UPDATE semantic_execution_cache \
                 SET input_embedding = $1::vector \
                 WHERE id = $2",
            )
            .bind(&embedding_str)
            .bind(row_id)
            .execute(&pool)
            .await
            {
                tracing::warn!(row_id = %row_id, "Cache embedding update failed: {}", e);
            }
        });
    }

    // ── Tagging ───────────────────────────────────────────────────────────

    /// Get the current tag count for a workflow.
    pub async fn get_tag_count(&self, workflow_id: Uuid, user_id: Uuid) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT coalesce(array_length(tags, 1), 0) FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?
        .unwrap_or(0);
        Ok(count)
    }

    /// Add a tag to a workflow (idempotent — skips if already present). Returns rows affected.
    pub async fn add_tag(&self, workflow_id: Uuid, user_id: Uuid, tag: &str) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflows SET tags = array_append(tags, $1) \
             WHERE id = $2 AND user_id = $3 AND NOT ($1 = ANY(tags))",
        )
        .bind(tag)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Remove a tag from a workflow. Returns rows affected.
    pub async fn remove_tag(&self, workflow_id: Uuid, user_id: Uuid, tag: &str) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflows SET tags = array_remove(tags, $1) \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(tag)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Batch-add a tag to multiple workflows. Returns total rows affected.
    pub async fn bulk_add_tag(
        &self,
        workflow_ids: &[Uuid],
        user_id: Uuid,
        tag: &str,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflows SET tags = array_append(tags, $1) \
             WHERE id = ANY($2) AND user_id = $3 AND NOT ($1 = ANY(tags))",
        )
        .bind(tag)
        .bind(workflow_ids)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// MCP-152 (2026-05-08): Count how many of the supplied workflow ids are
    /// actually owned by `user_id`. Pairs with `bulk_add_tag` so callers can
    /// disambiguate not-found / not-owned from already-tagged: previously the
    /// bulk tag handler reported `already_tagged_count = total - tagged`,
    /// which silently swallowed nonexistent UUIDs as "already tagged" and
    /// hid typos in operator input.
    pub async fn count_owned_workflows_in_set(
        &self,
        workflow_ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<u64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM workflows \
             WHERE id = ANY($1) AND user_id = $2",
        )
        .bind(workflow_ids)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(row.0.max(0) as u64)
    }

    /// Set the embedding vector for a workflow.
    pub async fn set_workflow_embedding(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        embedding: &[f64],
    ) -> Result<bool> {
        let emb_str = format!(
            "[{}]",
            embedding
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let result = sqlx::query(
            "UPDATE workflows SET embedding = $1::vector, updated_at = NOW() \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(&emb_str)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    // ── utils.rs MCP-handler support (search_text rebuild) ────────────────

    /// Source columns for `update_workflow_search_text` — name + the four
    /// inputs that get joined into the search text. Distinct from
    /// `WorkflowEmbeddingSource` which omits graph_json (the embedding text
    /// only uses node names indirectly via capabilities).
    pub async fn get_workflow_for_search_text_rebuild(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WorkflowSearchTextSource>> {
        let row = sqlx::query(
            "SELECT name, description, intent, capabilities, graph_json \
             FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.map(|r| WorkflowSearchTextSource {
            name: r.get("name"),
            description: r.try_get("description").unwrap_or(None),
            intent: r.try_get("intent").unwrap_or(None),
            capabilities: r.try_get("capabilities").unwrap_or_default(),
            graph_json: r.try_get("graph_json").unwrap_or(None),
        }))
    }

    /// Update the `search_text` column on a workflow (best-effort).
    /// No user_id scope — caller has already verified ownership via the
    /// preceding `get_workflow_for_search_text_rebuild` lookup.
    pub async fn set_workflow_search_text(&self, workflow_id: Uuid, text: &str) -> Result<()> {
        sqlx::query("UPDATE workflows SET search_text = $1 WHERE id = $2")
            .bind(text)
            .bind(workflow_id)
            .execute(&self.db_pool)
            .await?;
        Ok(())
    }

    // ── workflows.rs MCP-handler support ───────────────────────────────────

    /// Insert a published, internal-type workflow with an actor_id. Used by
    /// `plan_and_execute_workflow` for both subtask workflows and the
    /// orchestrator workflow. `graph_json` is bound as text and cast to JSONB.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_published_internal_workflow(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        actor_id: Option<Uuid>,
        name: &str,
        description: &str,
        graph_json: &str,
    ) -> Result<()> {
        sqlx::query(
            // RFC 0004: stamp org_id = the creator's personal org (NULL-tolerant).
            "INSERT INTO workflows (id, user_id, actor_id, name, description, graph_json, status, workflow_type, org_id) \
             VALUES ($1, $2, $3, $4, $5, $6::jsonb, 'published', 'internal', \
              (SELECT id FROM organizations WHERE owner_id = $2 AND is_personal))",
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(actor_id)
        .bind(name)
        .bind(description)
        .bind(graph_json)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Insert a workflow created from a YAML import. Distinct from
    /// `create_workflow_basic` because this variant carries
    /// `capabilities` + a placeholder `module_uri` and sets `is_enabled = true`.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_yaml_imported_workflow(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        name: &str,
        description: &str,
        graph_json: &str,
        capabilities: &[String],
        module_uri: &str,
    ) -> Result<()> {
        sqlx::query(
            // RFC 0004: stamp org_id = the creator's personal org (NULL-tolerant).
            "INSERT INTO workflows (id, user_id, name, description, graph_json, is_enabled, capabilities, module_uri, org_id) \
             VALUES ($1, $2, $3, $4, $5, true, $6, $7, \
              (SELECT id FROM organizations WHERE owner_id = $2 AND is_personal))",
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(name)
        .bind(description)
        .bind(graph_json)
        .bind(capabilities)
        .bind(module_uri)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    // ── versions.rs MCP-handler support ────────────────────────────────────

    /// Optionally update `intent` and/or `capabilities` on a workflow.
    /// COALESCE-based so passing `None` preserves the existing column value.
    /// Sidecar bools (`update_intent`, `update_capabilities`) distinguish
    /// "caller did not pass" from "caller cleared to NULL"; same idiom
    /// `update_actor_name_description` uses for description.
    pub async fn update_workflow_intent_and_capabilities(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        intent: Option<&serde_json::Value>,
        capabilities: Option<&[String]>,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflows SET \
                intent = CASE WHEN $3::bool THEN $4 ELSE intent END, \
                capabilities = CASE WHEN $5::bool THEN $6 ELSE capabilities END \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(intent.is_some())
        .bind(intent)
        .bind(capabilities.is_some())
        .bind(capabilities)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Update the `status` column on a workflow (e.g. "active", "archived").
    pub async fn set_workflow_status(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        status: &str,
    ) -> Result<u64> {
        let result = sqlx::query("UPDATE workflows SET status = $1 WHERE id = $2 AND user_id = $3")
            .bind(status)
            .bind(workflow_id)
            .bind(user_id)
            .execute(&self.db_pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Fetch `(version_id, graph_json::text)` for a (workflow_id, version_number)
    /// pair, scoped to the caller. Used by `rollback_workflow`.
    ///
    /// Defense-in-depth: the JOIN on `workflows.user_id` makes this fail
    /// closed if a future caller forgets the upstream ownership check —
    /// matches the r274 pattern for `get_active_version_graph`.
    pub async fn get_version_by_number(
        &self,
        workflow_id: Uuid,
        version_number: i32,
        user_id: Uuid,
    ) -> Result<Option<(Uuid, String)>> {
        let row: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT v.id, v.graph_json::text \
             FROM workflow_versions v \
             JOIN workflows w ON w.id = v.workflow_id \
             WHERE v.workflow_id = $1 AND v.version_number = $2 AND w.user_id = $3",
        )
        .bind(workflow_id)
        .bind(version_number)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row)
    }

    /// Fetch just the `graph_json::text` for a (workflow_id, version_number)
    /// pair, scoped to the caller. Used by `diff_versions`.
    pub async fn get_version_graph_text_by_number(
        &self,
        workflow_id: Uuid,
        version_number: i32,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT v.graph_json::text \
             FROM workflow_versions v \
             JOIN workflows w ON w.id = v.workflow_id \
             WHERE v.workflow_id = $1 AND v.version_number = $2 AND w.user_id = $3",
        )
        .bind(workflow_id)
        .bind(version_number)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.map(|(g,)| g))
    }

    /// Fetch the `graph_json::text` for the currently-active published
    /// version. Used by `get_version_diff_summary` to compare draft vs.
    /// published. Returns Ok(None) when no version is active yet.
    pub async fn get_active_version_graph_text(&self, workflow_id: Uuid) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT graph_json::text FROM workflow_versions \
             WHERE workflow_id = $1 AND is_active = true",
        )
        .bind(workflow_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.map(|(g,)| g))
    }

    // ── schedules.rs MCP-handler support ───────────────────────────────────

    /// 24-hour execution stats for a single workflow — total / succeeded /
    /// failed counts plus the last successful and last failed `started_at`.
    /// Used by `get_schedule_health`. Distinct from
    /// `get_workflow_queue_stats_24h` (which is user-scoped + queued/cancelled
    /// counts); this variant is workflow-only and tracks first-success /
    /// first-failure timestamps.
    pub async fn get_workflow_24h_execution_stats(
        &self,
        workflow_id: Uuid,
    ) -> Result<WorkflowHealthStats> {
        let row = sqlx::query(
            "SELECT \
                COUNT(*)::bigint AS total, \
                COUNT(*) FILTER (WHERE status = 'completed')::bigint AS succeeded, \
                COUNT(*) FILTER (WHERE status = 'failed')::bigint AS failed, \
                MAX(CASE WHEN status = 'completed' THEN started_at END) AS last_success_at, \
                MAX(CASE WHEN status = 'failed' THEN started_at END) AS last_failure_at \
             FROM workflow_executions \
             WHERE workflow_id = $1 AND started_at > NOW() - interval '24 hours'",
        )
        .bind(workflow_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(WorkflowHealthStats {
            total: row.try_get("total").unwrap_or(0),
            succeeded: row.try_get("succeeded").unwrap_or(0),
            failed: row.try_get("failed").unwrap_or(0),
            last_success_at: row.try_get("last_success_at").unwrap_or(None),
            last_failure_at: row.try_get("last_failure_at").unwrap_or(None),
        })
    }

    /// Like [`get_workflow_24h_execution_stats`] but filters to
    /// runs triggered by the scheduler. Used by `get_schedule_health`
    /// so manual `test_workflow` / `trigger_workflow` / webhook /
    /// approval-continuation runs don't pollute the schedule's
    /// success-rate and streak numbers.
    ///
    /// `workflow_executions` does NOT have a top-level `trigger_type`
    /// column (only `node_executions` does, per migration `012_node_executions.sql`).
    /// trigger_type lives in the `provenance` JSONB column —
    /// `provenance->>'trigger_type'` is the canonical projection,
    /// matching `ExecutionRepository::get_execution_base` line 1608.
    /// Pre-fix this query referenced the non-existent top-level
    /// column, errored at runtime, and the handler's `unwrap_or`
    /// returned zeros for every scheduled workflow.
    pub async fn get_scheduled_24h_execution_stats(
        &self,
        workflow_id: Uuid,
    ) -> Result<WorkflowHealthStats> {
        let row = sqlx::query(
            "SELECT \
                COUNT(*)::bigint AS total, \
                COUNT(*) FILTER (WHERE status = 'completed')::bigint AS succeeded, \
                COUNT(*) FILTER (WHERE status = 'failed')::bigint AS failed, \
                MAX(CASE WHEN status = 'completed' THEN started_at END) AS last_success_at, \
                MAX(CASE WHEN status = 'failed' THEN started_at END) AS last_failure_at \
             FROM workflow_executions \
             WHERE workflow_id = $1 \
               AND provenance->>'trigger_type' = 'scheduled' \
               AND started_at > NOW() - interval '24 hours'",
        )
        .bind(workflow_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(WorkflowHealthStats {
            total: row.try_get("total").unwrap_or(0),
            succeeded: row.try_get("succeeded").unwrap_or(0),
            failed: row.try_get("failed").unwrap_or(0),
            last_success_at: row.try_get("last_success_at").unwrap_or(None),
            last_failure_at: row.try_get("last_failure_at").unwrap_or(None),
        })
    }

    /// Recent execution statuses for a workflow (newest first), used by
    /// `get_schedule_health` to compute streak length and last-success-ago.
    pub async fn list_recent_workflow_execution_statuses(
        &self,
        workflow_id: Uuid,
        limit: i64,
    ) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT status FROM workflow_executions \
             WHERE workflow_id = $1 ORDER BY started_at DESC LIMIT $2",
        )
        .bind(workflow_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows.into_iter().map(|(s,)| s).collect())
    }

    /// Schedule-scoped variant of
    /// [`list_recent_workflow_execution_statuses`]. Filters to
    /// scheduler-fired runs via `provenance->>'trigger_type'` so
    /// streak + last-success-ago reflect scheduled runs only. See
    /// the doc comment on `get_scheduled_24h_execution_stats` for
    /// why `provenance->>` rather than a top-level column.
    pub async fn list_recent_scheduled_execution_statuses(
        &self,
        workflow_id: Uuid,
        limit: i64,
    ) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT status FROM workflow_executions \
             WHERE workflow_id = $1 AND provenance->>'trigger_type' = 'scheduled' \
             ORDER BY started_at DESC LIMIT $2",
        )
        .bind(workflow_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows.into_iter().map(|(s,)| s).collect())
    }

    // ── graph.rs MCP-handler support ───────────────────────────────────────

    /// Returns true if the workflow has an active published version. Used
    /// 4× by graph mutation handlers as a gate for the auto-publish sync.
    pub async fn workflow_has_active_version(&self, workflow_id: Uuid) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM workflow_versions WHERE workflow_id = $1 AND is_active = true)",
        )
        .bind(workflow_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(exists)
    }

    /// Source-workflow projection for `duplicate_workflow` — name, raw
    /// graph_json text, and tags only.
    pub async fn get_workflow_for_duplicate(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WorkflowDuplicateSource>> {
        let row = sqlx::query(
            "SELECT name, graph_json, tags FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.map(|r| WorkflowDuplicateSource {
            name: r.try_get("name").unwrap_or_default(),
            graph_json: r.try_get("graph_json").unwrap_or_else(|_| "{}".to_string()),
            tags: r.try_get("tags").unwrap_or_default(),
        }))
    }

    /// Insert a duplicated workflow row. Returns the DB error so callers
    /// can decide between "duplicate-name" and generic-failure messaging.
    pub async fn insert_duplicated_workflow(
        &self,
        new_id: Uuid,
        user_id: Uuid,
        new_name: &str,
        graph_json: &str,
        tags: &[String],
    ) -> Result<()> {
        sqlx::query(
            // RFC 0004: stamp org_id = the creator's personal org (NULL-tolerant).
            "INSERT INTO workflows (id, user_id, name, module_uri, graph_json, tags, created_at, updated_at, org_id) \
             VALUES ($1, $2, $3, '', $4, $5, NOW(), NOW(), \
              (SELECT id FROM organizations WHERE owner_id = $2 AND is_personal))",
        )
        .bind(new_id)
        .bind(user_id)
        .bind(new_name)
        .bind(graph_json)
        .bind(tags)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Copy `input_schema` from one workflow to another (caller already
    /// verified ownership of both). Best-effort — returns Err on DB failure
    /// but the duplicate-workflow handler swallows it as non-fatal.
    pub async fn copy_input_schema(
        &self,
        source_workflow_id: Uuid,
        target_workflow_id: Uuid,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE workflows SET input_schema = (SELECT input_schema FROM workflows WHERE id = $1) \
             WHERE id = $2",
        )
        .bind(source_workflow_id)
        .bind(target_workflow_id)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Find workflows whose `capabilities` array is a superset of the given
    /// list — matches the engine's runtime capability-dispatch SQL exactly
    /// (parallel.rs:2715-2718). Used by `preview_capability_dispatch`.
    pub async fn find_workflows_for_capability_dispatch_preview(
        &self,
        user_id: Uuid,
        required_caps: &[String],
        limit: i64,
    ) -> Result<Vec<CapabilityDispatchPreviewRow>> {
        let rows = sqlx::query(
            "SELECT id, name, capabilities, readiness_score, status, updated_at \
             FROM workflows \
             WHERE user_id = $1 \
               AND capabilities @> $2 \
             ORDER BY updated_at DESC \
             LIMIT $3",
        )
        .bind(user_id)
        .bind(required_caps)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| CapabilityDispatchPreviewRow {
                id: r.try_get("id").unwrap_or_default(),
                name: r.try_get("name").unwrap_or_default(),
                capabilities: r.try_get("capabilities").unwrap_or_default(),
                readiness_score: r.try_get("readiness_score").unwrap_or(None),
                status: r.try_get("status").unwrap_or_default(),
                updated_at: r.try_get("updated_at").unwrap_or(None),
            })
            .collect())
    }

    // ── configuration.rs MCP-handler support ───────────────────────────────

    /// List module names by id, NOT scoped to user. Used by
    /// `get_workflow_graph` for label resolution — the workflow's ownership is
    /// already verified, and exposing module names referenced from one's own
    /// graph is intentional (system + cross-user catalog labels are public).
    ///
    /// Phase 5.1: reads from the unified `modules` table by canonical id.
    pub async fn list_wasm_module_names_by_ids_unscoped(
        &self,
        ids: &[Uuid],
    ) -> Result<Vec<(Uuid, String)>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let rows: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT id, name FROM modules WHERE id = ANY($1)")
                .bind(ids)
                .fetch_all(&self.db_pool)
                .await?;
        Ok(rows)
    }

    /// `(id, capability_world)` for modules — same unscoped semantics as
    /// `list_wasm_module_names_by_ids_unscoped`. Complements
    /// `list_template_world_overrides`.
    ///
    /// Phase 5.1: reads from the unified `modules` table by canonical id.
    pub async fn list_wasm_module_worlds_by_ids(
        &self,
        ids: &[Uuid],
    ) -> Result<Vec<(Uuid, String)>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let rows: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT id, capability_world FROM modules WHERE id = ANY($1)")
                .bind(ids)
                .fetch_all(&self.db_pool)
                .await?;
        Ok(rows)
    }

    /// Get a workflow's name by id, NOT scoped to user. Used by the
    /// `get_workflow_graph` sub-workflow label resolver — sub-workflow names
    /// are visible from a workflow that already passed ownership check.
    pub async fn get_workflow_name_by_id(&self, workflow_id: Uuid) -> Result<Option<String>> {
        let name: Option<String> = sqlx::query_scalar("SELECT name FROM workflows WHERE id = $1")
            .bind(workflow_id)
            .fetch_optional(&self.db_pool)
            .await?;
        Ok(name)
    }

    /// Update the raw `graph_json` column for a workflow scoped to user.
    /// Used by handlers that mutate the JSON in-Rust then write it back
    /// (e.g. `set_workflow_priority`).
    pub async fn update_workflow_graph_json(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        graph_json: &str,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflows SET graph_json = $1, updated_at = NOW() \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(graph_json)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Just the workflow's name for ownership check — used by
    /// `get_workflow_input_schema` to verify ownership before scanning
    /// execution outputs.
    pub async fn get_workflow_name_for_user(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT name FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(workflow_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(row.map(|(n,)| n))
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
                        Ok(s) => serde_json::from_str(&s)
                            .unwrap_or_else(|_| serde_json::json!({})),
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

    /// Update the `intent` JSONB column on a workflow.
    pub async fn set_workflow_intent_field(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        intent: &serde_json::Value,
    ) -> Result<u64> {
        let result = sqlx::query("UPDATE workflows SET intent = $1 WHERE id = $2 AND user_id = $3")
            .bind(intent)
            .bind(workflow_id)
            .bind(user_id)
            .execute(&self.db_pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Top N workflows by readiness_score (NULLS LAST). Used by
    /// `get_session_context` to surface the user's most production-ready
    /// workflows first.
    pub async fn list_top_workflows_by_readiness(
        &self,
        user_id: Uuid,
        limit: i32,
    ) -> Result<Vec<SessionContextWorkflowRow>> {
        let rows = sqlx::query(
            "SELECT id, name, capabilities, readiness_score, graph_json \
             FROM workflows WHERE user_id = $1 \
             ORDER BY readiness_score DESC NULLS LAST \
             LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| SessionContextWorkflowRow {
                id: r.get("id"),
                name: r.get("name"),
                capabilities: r.try_get("capabilities").unwrap_or_default(),
                readiness_score: r.try_get("readiness_score").unwrap_or(None),
                graph_json: r.try_get("graph_json").unwrap_or_default(),
            })
            .collect())
    }

    /// Most-recently-used workflows for a user via `workflow_reuse_events`.
    /// DISTINCT ON keeps only the latest reuse per workflow.
    pub async fn list_recently_used_workflows(
        &self,
        user_id: Uuid,
        limit: i32,
    ) -> Result<Vec<RecentlyUsedWorkflowRow>> {
        let rows = sqlx::query(
            "SELECT DISTINCT ON (r.workflow_id) r.workflow_id, w.name, w.capabilities \
             FROM workflow_reuse_events r \
             JOIN workflows w ON w.id = r.workflow_id AND w.user_id = $1 \
             ORDER BY r.workflow_id, r.created_at DESC \
             LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| RecentlyUsedWorkflowRow {
                workflow_id: r.get("workflow_id"),
                name: r.try_get("name").unwrap_or_default(),
                capabilities: r.try_get("capabilities").unwrap_or_default(),
            })
            .collect())
    }

    /// Keyword-match workflows by ILIKE on name/description/capabilities. Used
    /// by `get_session_context` task-description matching.
    pub async fn match_workflows_by_keyword(
        &self,
        user_id: Uuid,
        ilike_pattern: &str,
        limit: i32,
    ) -> Result<Vec<RecentlyUsedWorkflowRow>> {
        let rows = sqlx::query(
            "SELECT id, name, capabilities FROM workflows \
             WHERE user_id = $1 \
               AND (name ILIKE $2 OR description ILIKE $2 OR array_to_string(capabilities, ' ') ILIKE $2) \
             LIMIT $3",
        )
        .bind(user_id)
        .bind(ilike_pattern)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| RecentlyUsedWorkflowRow {
                workflow_id: r.get("id"),
                name: r.try_get("name").unwrap_or_default(),
                capabilities: r.try_get("capabilities").unwrap_or_default(),
            })
            .collect())
    }

    /// Full identity row for `get_workflow_identity`.
    pub async fn get_workflow_identity_row(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WorkflowIdentityRow>> {
        let row = sqlx::query(
            "SELECT id, name, description, capabilities, intent, readiness_score, readiness_computed_at, graph_json, input_schema \
             FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.map(|r| WorkflowIdentityRow {
            name: r.get("name"),
            description: r.try_get("description").unwrap_or(None),
            capabilities: r.try_get("capabilities").unwrap_or_default(),
            intent: r.try_get("intent").unwrap_or(None),
            readiness_score: r.try_get("readiness_score").unwrap_or(None),
            readiness_computed_at: r.try_get("readiness_computed_at").unwrap_or(None),
            graph_json: r.try_get("graph_json").unwrap_or_default(),
            input_schema: r.try_get("input_schema").unwrap_or(None),
        }))
    }

    // ── search.rs MCP-handler support ──────────────────────────────────────

    /// Fetch the embedding-source columns for a workflow. Used by
    /// `auto_embed_workflow` to compute the embedding text from
    /// `(name, description, capabilities, intent)`.
    pub async fn get_workflow_embedding_source(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WorkflowEmbeddingSource>> {
        let row = sqlx::query(
            "SELECT name, description, capabilities, intent FROM workflows \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.map(|r| WorkflowEmbeddingSource {
            name: r.try_get("name").unwrap_or_default(),
            description: r.try_get("description").unwrap_or(None),
            capabilities: r.try_get("capabilities").unwrap_or_default(),
            intent: r.try_get("intent").unwrap_or(None),
        }))
    }

    /// Set the embedding column from a pre-formatted pgvector literal string
    /// (`"[0.1,0.2,...]"`). The `auto_embed_workflow` and
    /// `generate_workflow_embeddings` paths share this; the typed
    /// `set_workflow_embedding` (above) builds the string for them.
    pub async fn set_workflow_embedding_from_str(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        embedding_str: &str,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflows SET embedding = $1::vector WHERE id = $2 AND user_id = $3",
        )
        .bind(embedding_str)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Batch sibling to [`set_workflow_embedding_from_str`]. Single
    /// `UPDATE … FROM UNNEST(...)` round-trip applies all (workflow_id,
    /// embedding) pairs in one statement, replacing the per-workflow
    /// loop used by `handle_generate_workflow_embeddings` (up to 200
    /// round-trips per call → 1).
    ///
    /// Returns the number of rows actually updated. A row that no longer
    /// exists for `user_id` simply doesn't update and isn't counted —
    /// matching the per-row method's "0 rows affected" semantics for a
    /// missing target. Empty input short-circuits without touching the DB.
    ///
    /// Security: same user-bound scoping as the per-row method
    /// (`AND w.user_id = $3`) — an attacker passing a workflow_id they
    /// don't own contributes 0 to rows_affected, identical to the prior
    /// per-row behaviour.
    pub async fn bulk_set_workflow_embeddings_from_str(
        &self,
        pairs: &[(Uuid, String)],
        user_id: Uuid,
    ) -> Result<u64> {
        if pairs.is_empty() {
            return Ok(0);
        }
        let ids: Vec<Uuid> = pairs.iter().map(|(id, _)| *id).collect();
        let embs: Vec<String> = pairs.iter().map(|(_, e)| e.clone()).collect();
        let result = sqlx::query(
            "UPDATE workflows w \
             SET embedding = u.emb::vector \
             FROM UNNEST($1::uuid[], $2::text[]) AS u(id, emb) \
             WHERE w.id = u.id AND w.user_id = $3",
        )
        .bind(&ids)
        .bind(&embs)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Keyword search by `name ILIKE` with optional `tag` filter and
    /// `include_archived` flag. Used by `handle_search_workflows`.
    pub async fn search_workflows_by_name_ilike(
        &self,
        user_id: Uuid,
        ilike_pattern: &str,
        tag_filter: Option<&str>,
        include_archived: bool,
        limit: i64,
    ) -> Result<Vec<WorkflowSearchRow>> {
        let rows = if let Some(tag) = tag_filter {
            sqlx::query(
                "SELECT id, name, description, tags, status, created_at, updated_at \
                 FROM workflows WHERE user_id = $1 AND name ILIKE $2 AND $3 = ANY(tags) \
                 AND ($4 OR COALESCE(status, '') != 'archived') \
                 ORDER BY updated_at DESC LIMIT $5",
            )
            .bind(user_id)
            .bind(ilike_pattern)
            .bind(tag)
            .bind(include_archived)
            .bind(limit)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, name, description, tags, status, created_at, updated_at \
                 FROM workflows WHERE user_id = $1 AND name ILIKE $2 \
                 AND ($3 OR COALESCE(status, '') != 'archived') \
                 ORDER BY updated_at DESC LIMIT $4",
            )
            .bind(user_id)
            .bind(ilike_pattern)
            .bind(include_archived)
            .bind(limit)
            .fetch_all(&self.db_pool)
            .await?
        };
        Ok(rows
            .iter()
            .map(|r| WorkflowSearchRow {
                id: r.get("id"),
                name: r.get("name"),
                description: r.try_get("description").unwrap_or(None),
                tags: r.try_get("tags").unwrap_or_default(),
                status: r.try_get("status").unwrap_or(None),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
            })
            .collect())
    }

    /// Fetch the source-workflow graph_json string for `find_similar_workflows`.
    /// Returns Ok(None) when the workflow doesn't exist or isn't owned.
    pub async fn get_workflow_graph_for_similarity(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT graph_json FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(workflow_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(row.map(|(g,)| g))
    }

    /// List the user's other workflows for module-overlap similarity scoring.
    /// Caps at 200 rows (heuristic similarity scan, not a paginated view).
    pub async fn list_workflows_for_similarity(
        &self,
        user_id: Uuid,
        exclude_id: Uuid,
        limit: i64,
    ) -> Result<Vec<WorkflowGraphRow>> {
        let rows = sqlx::query(
            "SELECT id, name, graph_json FROM workflows WHERE user_id = $1 AND id != $2 \
             AND (status IS NULL OR status != 'archived') LIMIT $3",
        )
        .bind(user_id)
        .bind(exclude_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| WorkflowGraphRow {
                id: r.get("id"),
                name: r.get("name"),
                graph_json: r.get("graph_json"),
            })
            .collect())
    }

    /// Vector cosine search over the workflows.embedding column.
    /// `embedding_str` must be in pgvector literal form.
    ///
    /// N T5-N2: `include_archived: bool` is a typed boolean, not a SQL
    /// fragment. Pre-fix the parameter was `archived_clause: &str`
    /// interpolated into the SQL via `format!()` — safe today because
    /// the only caller branched on a closed boolean, but a future
    /// caller forwarding user input could trip the SQL-fragment
    /// injection footgun. The bool is now bound via `$N` like every
    /// other parameter and the SQL string is fully parameterised.
    pub async fn search_workflows_by_embedding(
        &self,
        user_id: Uuid,
        embedding_str: &str,
        tag_filter: Option<&str>,
        include_archived: bool,
        limit: i32,
    ) -> Result<Vec<WorkflowSemanticVectorRow>, sqlx::Error> {
        let rows = if let Some(tag) = tag_filter {
            sqlx::query(
                "SELECT id, name, description, capabilities, readiness_score, \
                        1 - (embedding <=> $2::vector) AS match_score \
                 FROM workflows WHERE user_id = $1 AND embedding IS NOT NULL \
                    AND ($5 OR COALESCE(status, '') != 'archived') \
                    AND $4 = ANY(tags) \
                 ORDER BY embedding <=> $2::vector \
                 LIMIT $3",
            )
            .bind(user_id)
            .bind(embedding_str)
            .bind(limit)
            .bind(tag)
            .bind(include_archived)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, name, description, capabilities, readiness_score, \
                        1 - (embedding <=> $2::vector) AS match_score \
                 FROM workflows WHERE user_id = $1 AND embedding IS NOT NULL \
                    AND ($4 OR COALESCE(status, '') != 'archived') \
                 ORDER BY embedding <=> $2::vector \
                 LIMIT $3",
            )
            .bind(user_id)
            .bind(embedding_str)
            .bind(limit)
            .bind(include_archived)
            .fetch_all(&self.db_pool)
            .await?
        };
        Ok(rows
            .iter()
            .map(|r| WorkflowSemanticVectorRow {
                id: r.get("id"),
                name: r.get("name"),
                description: r.get("description"),
                capabilities: r.get("capabilities"),
                readiness_score: r.get("readiness_score"),
                match_score: r.try_get("match_score").unwrap_or(0.0),
            })
            .collect())
    }

    /// pg_trgm fuzzy keyword search with ILIKE fallback OR. Returns
    /// `(id, name, description, capabilities, intent, readiness_score, match_score)`.
    ///
    /// N T5-N2: `include_archived: bool` (typed parameter, not SQL
    /// fragment) — same fix as `search_workflows_by_embedding`.
    pub async fn search_workflows_trgm(
        &self,
        user_id: Uuid,
        query_str: &str,
        ilike_pattern: &str,
        tag_filter: Option<&str>,
        include_archived: bool,
        limit: i32,
    ) -> Result<Vec<WorkflowSemanticTrgmRow>, sqlx::Error> {
        let rows = if let Some(tag) = tag_filter {
            sqlx::query(
                "SELECT id, name, description, capabilities, intent, readiness_score, \
                    GREATEST( \
                        similarity(name, $2), \
                        similarity(COALESCE(description, ''), $2), \
                        similarity(array_to_string(capabilities, ' '), $2), \
                        similarity(COALESCE(search_text, ''), $2) \
                    ) AS match_score \
                 FROM workflows WHERE user_id = $1 \
                    AND ($6 OR COALESCE(status, '') != 'archived') \
                    AND $5 = ANY(tags) \
                    AND (similarity(name, $2) > 0.1 OR similarity(COALESCE(description, ''), $2) > 0.1 \
                         OR similarity(COALESCE(search_text, ''), $2) > 0.1 \
                         OR name ILIKE $3 OR COALESCE(description, '') ILIKE $3 OR COALESCE(search_text, '') ILIKE $3) \
                 ORDER BY match_score DESC LIMIT $4",
            )
            .bind(user_id)
            .bind(query_str)
            .bind(ilike_pattern)
            .bind(limit)
            .bind(tag)
            .bind(include_archived)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, name, description, capabilities, intent, readiness_score, \
                    GREATEST( \
                        similarity(name, $2), \
                        similarity(COALESCE(description, ''), $2), \
                        similarity(array_to_string(capabilities, ' '), $2), \
                        similarity(COALESCE(search_text, ''), $2) \
                    ) AS match_score \
                 FROM workflows WHERE user_id = $1 \
                    AND ($5 OR COALESCE(status, '') != 'archived') \
                    AND (similarity(name, $2) > 0.1 OR similarity(COALESCE(description, ''), $2) > 0.1 \
                         OR similarity(COALESCE(search_text, ''), $2) > 0.1 \
                         OR name ILIKE $3 OR COALESCE(description, '') ILIKE $3 OR COALESCE(search_text, '') ILIKE $3) \
                 ORDER BY match_score DESC LIMIT $4",
            )
            .bind(user_id)
            .bind(query_str)
            .bind(ilike_pattern)
            .bind(limit)
            .bind(include_archived)
            .fetch_all(&self.db_pool)
            .await?
        };
        Ok(rows
            .iter()
            .map(|r| WorkflowSemanticTrgmRow {
                id: r.get("id"),
                name: r.get("name"),
                description: r.try_get("description").unwrap_or(None),
                capabilities: r.try_get("capabilities").unwrap_or_default(),
                intent: r.try_get("intent").unwrap_or(None),
                readiness_score: r.try_get("readiness_score").unwrap_or(None),
                match_score: r
                    .try_get::<Option<f32>, _>("match_score")
                    .ok()
                    .flatten()
                    .map(|f| f as f64),
            })
            .collect())
    }

    /// ILIKE-only fallback for `search_workflows_trgm` when pg_trgm is
    /// unavailable. Same projection minus the `match_score` (keyword fallback
    /// has none).
    ///
    /// N T5-N2: `include_archived: bool` (typed parameter, not SQL
    /// fragment) — same fix as `search_workflows_by_embedding`.
    pub async fn search_workflows_ilike_fallback(
        &self,
        user_id: Uuid,
        ilike_pattern: &str,
        tag_filter: Option<&str>,
        include_archived: bool,
        limit: i32,
    ) -> Result<Vec<WorkflowSemanticTrgmRow>, sqlx::Error> {
        let rows = if let Some(tag) = tag_filter {
            sqlx::query(
                "SELECT id, name, description, capabilities, intent, readiness_score \
                 FROM workflows WHERE user_id = $1 \
                    AND ($5 OR COALESCE(status, '') != 'archived') \
                    AND $4 = ANY(tags) \
                    AND (name ILIKE $2 OR description ILIKE $2 OR array_to_string(capabilities, ' ') ILIKE $2 OR intent::text ILIKE $2 OR COALESCE(search_text, '') ILIKE $2) \
                 ORDER BY readiness_score DESC NULLS LAST \
                 LIMIT $3",
            )
            .bind(user_id)
            .bind(ilike_pattern)
            .bind(limit)
            .bind(tag)
            .bind(include_archived)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, name, description, capabilities, intent, readiness_score \
                 FROM workflows WHERE user_id = $1 \
                    AND ($4 OR COALESCE(status, '') != 'archived') \
                    AND (name ILIKE $2 OR description ILIKE $2 OR array_to_string(capabilities, ' ') ILIKE $2 OR intent::text ILIKE $2 OR COALESCE(search_text, '') ILIKE $2) \
                 ORDER BY readiness_score DESC NULLS LAST \
                 LIMIT $3",
            )
            .bind(user_id)
            .bind(ilike_pattern)
            .bind(limit)
            .bind(include_archived)
            .fetch_all(&self.db_pool)
            .await?
        };
        Ok(rows
            .iter()
            .map(|r| WorkflowSemanticTrgmRow {
                id: r.get("id"),
                name: r.get("name"),
                description: r.try_get("description").unwrap_or(None),
                capabilities: r.try_get("capabilities").unwrap_or_default(),
                intent: r.try_get("intent").unwrap_or(None),
                readiness_score: r.try_get("readiness_score").unwrap_or(None),
                match_score: None,
            })
            .collect())
    }

    /// Workflows that need embedding regeneration. When `force_refresh` is
    /// true, returns all rows; otherwise only rows where `embedding IS NULL`.
    pub async fn list_workflows_for_embedding_generation(
        &self,
        user_id: Uuid,
        force_refresh: bool,
        limit: i32,
    ) -> Result<Vec<WorkflowEmbeddingCandidate>> {
        let rows = if force_refresh {
            sqlx::query(
                "SELECT id, name, description, capabilities, intent \
                 FROM workflows WHERE user_id = $1 \
                 ORDER BY updated_at DESC LIMIT $2",
            )
            .bind(user_id)
            .bind(limit)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, name, description, capabilities, intent \
                 FROM workflows WHERE user_id = $1 AND embedding IS NULL \
                 ORDER BY updated_at DESC LIMIT $2",
            )
            .bind(user_id)
            .bind(limit)
            .fetch_all(&self.db_pool)
            .await?
        };
        Ok(rows
            .iter()
            .map(|r| WorkflowEmbeddingCandidate {
                id: r.try_get("id").unwrap_or_default(),
                name: r.try_get("name").unwrap_or_default(),
                description: r.try_get("description").unwrap_or(None),
                capabilities: r.try_get("capabilities").unwrap_or_default(),
                intent: r.try_get("intent").unwrap_or(None),
            })
            .collect())
    }

    // ── platform.rs MCP-handler support ────────────────────────────────────

    /// Update the failure_webhook_url column on a workflow. Pass `None` to clear.
    /// Returns rows affected (0 = workflow not found / not owned).
    /// Distinct from the `workflow_webhooks` table — this is a single-column
    /// shortcut for the legacy MCP `set_failure_notification` tool.
    pub async fn set_failure_webhook_url_column(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        url: Option<&str>,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflows SET failure_webhook_url = $1 WHERE id = $2 AND user_id = $3",
        )
        .bind(url)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Fetch the legacy `workflows.failure_webhook_url` column. Outer Option
    /// = workflow found vs. not found; inner = column NULL vs. set.
    /// Distinct from `get_failure_webhook_url`, which queries the newer
    /// `workflow_webhooks` event-type table.
    pub async fn get_failure_webhook_url_column(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Option<String>>> {
        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT failure_webhook_url FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.map(|(u,)| u))
    }

    /// Set or clear the per-workflow concurrency cap.
    pub async fn set_max_concurrent_executions(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        max_concurrent: Option<i32>,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflows SET max_concurrent_executions = $1 WHERE id = $2 AND user_id = $3",
        )
        .bind(max_concurrent)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// List all workflows for a user with their optional schedule joined in.
    /// Used by `export_platform_state` to build the manifest. Returns rows
    /// including raw `graph_json` text for the caller to parse.
    pub async fn list_user_workflows_with_schedule(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<WorkflowExportRow>> {
        let rows = sqlx::query(
            "SELECT w.id, w.name, w.graph_json, w.is_enabled, \
                    ws.cron_expression, ws.timezone, ws.is_enabled AS schedule_enabled \
             FROM workflows w \
             LEFT JOIN workflow_schedules ws ON ws.workflow_id = w.id \
             WHERE w.user_id = $1 \
             ORDER BY w.created_at ASC",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| WorkflowExportRow {
                id: r.get("id"),
                name: r.get("name"),
                graph_json: r.get("graph_json"),
                is_enabled: r.try_get("is_enabled").unwrap_or(true),
                cron_expression: r.try_get("cron_expression").unwrap_or(None),
                timezone: r
                    .try_get::<Option<String>, _>("timezone")
                    .unwrap_or(None)
                    .unwrap_or_else(|| "UTC".to_string()),
                schedule_enabled: r.try_get("schedule_enabled").unwrap_or(true),
            })
            .collect())
    }

    /// Find a workflow by exact name match (regardless of status). Used by
    /// the `import_platform_state` upsert path which intentionally re-imports
    /// over archived workflows too.
    pub async fn find_workflow_id_by_name_any_status(
        &self,
        user_id: Uuid,
        name: &str,
    ) -> Result<Option<Uuid>> {
        let id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM workflows WHERE user_id = $1 AND name = $2 LIMIT 1")
                .bind(user_id)
                .bind(name)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(id)
    }

    /// Batch sibling to [`find_workflow_id_by_name_any_status`]. Replaces
    /// the per-name round-trip used by `import_platform_state`'s dry-run
    /// preview with a single `WHERE name = ANY($2)` lookup. Returns a
    /// `name → id` map; callers reading whether a name exists should
    /// use `.contains_key(name)` rather than zipping.
    ///
    /// Why this exists: a 5,000-workflow manifest's dry-run cost
    /// 5,001 round-trips pre-batch. Empty input short-circuits to an
    /// empty map without touching the DB.
    pub async fn find_workflow_ids_by_names_any_status(
        &self,
        user_id: Uuid,
        names: &[String],
    ) -> Result<std::collections::HashMap<String, Uuid>> {
        if names.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rows: Vec<(String, Uuid)> =
            sqlx::query_as("SELECT name, id FROM workflows WHERE user_id = $1 AND name = ANY($2)")
                .bind(user_id)
                .bind(names)
                .fetch_all(&self.db_pool)
                .await?;
        Ok(rows.into_iter().collect())
    }

    /// Insert-or-update a workflow's graph_json by (user_id, name). Returns
    /// the workflow id (existing or newly minted).
    pub async fn upsert_workflow_graph_by_name(
        &self,
        user_id: Uuid,
        name: &str,
        graph_json: &str,
        existing_id: Option<Uuid>,
    ) -> Result<Uuid> {
        let id: Uuid = if let Some(eid) = existing_id {
            // Defense-in-depth: scope the UPDATE by user_id even though the
            // caller resolved `existing_id` from a user-scoped lookup.
            // Failing closed (no row returned) protects against future
            // callers that forget the upstream check or accept an
            // attacker-supplied id.
            sqlx::query_scalar(
                "UPDATE workflows SET graph_json = $1, updated_at = NOW() \
                 WHERE id = $2 AND user_id = $3 RETURNING id",
            )
            .bind(graph_json)
            .bind(eid)
            .bind(user_id)
            .fetch_optional(&self.db_pool)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Workflow not found or not owned by caller"))?
        } else {
            sqlx::query_scalar(
                // RFC 0004: stamp org_id = the creator's personal org (NULL-tolerant).
                "INSERT INTO workflows (user_id, name, module_uri, graph_json, created_at, updated_at, org_id) \
                 VALUES ($1, $2, '', $3, NOW(), NOW(), \
                  (SELECT id FROM organizations WHERE owner_id = $1 AND is_personal)) \
                 RETURNING id",
            )
            .bind(user_id)
            .bind(name)
            .bind(graph_json)
            .fetch_one(&self.db_pool)
            .await?
        };
        Ok(id)
    }

    /// Upsert a workflow_schedules row for a workflow (one schedule per workflow).
    ///
    /// Defense-in-depth: the INSERT...SELECT predicate on `workflows.user_id`
    /// fails closed if the workflow doesn't belong to the caller — even if a
    /// future caller bypasses upstream ownership checks. We then verify rows
    /// were actually written and surface an error rather than silently no-op'ing.
    pub async fn upsert_workflow_schedule(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        cron: &str,
        timezone: &str,
        is_enabled: bool,
    ) -> Result<()> {
        let result = sqlx::query(
            "INSERT INTO workflow_schedules (workflow_id, user_id, cron_expression, timezone, is_enabled, created_at, updated_at) \
             SELECT $1, $2, $3, $4, $5, NOW(), NOW() \
             FROM workflows \
             WHERE id = $1 AND user_id = $2 \
             ON CONFLICT (workflow_id) DO UPDATE SET \
               cron_expression = EXCLUDED.cron_expression, \
               timezone = EXCLUDED.timezone, \
               is_enabled = EXCLUDED.is_enabled, \
               updated_at = NOW()",
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(cron)
        .bind(timezone)
        .bind(is_enabled)
        .execute(&self.db_pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(anyhow::anyhow!("Workflow not found or not owned by caller"));
        }
        Ok(())
    }

    /// Aggregated 24h queue stats for a workflow. Used by `get_queue_status`.
    pub async fn get_workflow_queue_stats_24h(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<WorkflowQueueStats> {
        let row = sqlx::query(
            "SELECT \
                COUNT(*) FILTER (WHERE status = 'queued')::bigint AS queued, \
                COUNT(*) FILTER (WHERE status = 'running')::bigint AS running, \
                COUNT(*) FILTER (WHERE status = 'completed')::bigint AS completed, \
                COUNT(*) FILTER (WHERE status = 'failed')::bigint AS failed, \
                COUNT(*) FILTER (WHERE status = 'cancelled')::bigint AS cancelled, \
                COUNT(*)::bigint AS total, \
                MIN(started_at) AS first_started, \
                MAX(completed_at) AS last_completed \
             FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 AND started_at > NOW() - interval '24 hours'",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(WorkflowQueueStats {
            queued: row.get("queued"),
            running: row.get("running"),
            completed: row.get("completed"),
            failed: row.get("failed"),
            cancelled: row.get("cancelled"),
            total: row.get("total"),
            first_started: row.try_get("first_started").unwrap_or(None),
            last_completed: row.try_get("last_completed").unwrap_or(None),
        })
    }
}

/// Source projection for `update_workflow_search_text`. Includes the raw
/// graph_json string — the helper extracts node labels from it before
/// composing the final search text.
#[derive(Debug)]
pub struct WorkflowSearchTextSource {
    pub name: String,
    pub description: Option<String>,
    pub intent: Option<serde_json::Value>,
    pub capabilities: Vec<String>,
    pub graph_json: Option<String>,
}

/// 24h workflow execution stats for `get_schedule_health`.
#[derive(Debug)]
pub struct WorkflowHealthStats {
    pub total: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub last_success_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_failure_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Source-workflow row for `duplicate_workflow`.
#[derive(Debug)]
pub struct WorkflowDuplicateSource {
    pub name: String,
    pub graph_json: String,
    pub tags: Vec<String>,
}

/// Row returned by `find_workflows_for_capability_dispatch_preview`.
#[derive(Debug)]
pub struct CapabilityDispatchPreviewRow {
    pub id: Uuid,
    pub name: String,
    pub capabilities: Vec<String>,
    pub readiness_score: Option<i32>,
    pub status: String,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Top-readiness row for `get_session_context`.
#[derive(Debug)]
pub struct SessionContextWorkflowRow {
    pub id: Uuid,
    pub name: String,
    pub capabilities: Vec<String>,
    pub readiness_score: Option<i32>,
    pub graph_json: String,
}

/// Recently-used / keyword-matched row for `get_session_context`.
#[derive(Debug)]
pub struct RecentlyUsedWorkflowRow {
    pub workflow_id: Uuid,
    pub name: String,
    pub capabilities: Vec<String>,
}

/// Identity projection for `get_workflow_identity`.
#[derive(Debug)]
pub struct WorkflowIdentityRow {
    pub name: String,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    pub intent: Option<serde_json::Value>,
    pub readiness_score: Option<i32>,
    pub readiness_computed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub graph_json: String,
    pub input_schema: Option<serde_json::Value>,
}

/// Source columns for `auto_embed_workflow` — name + the three free-text
/// inputs that get joined into the embedding text.
#[derive(Debug)]
pub struct WorkflowEmbeddingSource {
    pub name: String,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    pub intent: Option<serde_json::Value>,
}

/// Search row returned by `search_workflows_by_name_ilike`.
#[derive(Debug)]
pub struct WorkflowSearchRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub status: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Compact row for `list_workflows_for_similarity` — just enough to compute
/// module-overlap scores.
#[derive(Debug)]
pub struct WorkflowGraphRow {
    pub id: Uuid,
    pub name: String,
    pub graph_json: String,
}

/// Vector-search projection for `search_workflows_by_embedding`.
#[derive(Debug)]
pub struct WorkflowSemanticVectorRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    pub readiness_score: Option<i32>,
    pub match_score: f64,
}

/// pg_trgm/ILIKE projection for `search_workflows_trgm` and the
/// `search_workflows_ilike_fallback` fallback (which returns
/// `match_score = None`).
#[derive(Debug)]
pub struct WorkflowSemanticTrgmRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    pub intent: Option<serde_json::Value>,
    pub readiness_score: Option<i32>,
    pub match_score: Option<f64>,
}

/// Embedding-generation candidate row.
#[derive(Debug)]
pub struct WorkflowEmbeddingCandidate {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    pub intent: Option<serde_json::Value>,
}

/// Format an embedding vector as a pgvector literal (`"[v1,v2,…]"`).
///
/// pgvector accepts string literals via the `::vector` cast; this is the
/// canonical wire format used by `search_workflows_by_embedding`.
pub fn format_pgvector_literal(emb: &[f64]) -> String {
    let parts: Vec<String> = emb.iter().map(|v| v.to_string()).collect();
    format!("[{}]", parts.join(","))
}

/// Pure: extract candidate module-id UUIDs from a workflow graph `Value`.
///
/// Iterates `graph.nodes[*].type` and parses the string as a UUID. Any
/// non-UUID type (`"system:approval"`, custom strings, etc.) is silently
/// skipped — non-UUID types cannot be modules, so the filter is correct.
///
/// This is the `Value`-shaped sibling of
/// [`talos_workflow_authorization::extract_graph_module_ids`]
/// (which takes a `&str`); both `import_workflow` and `export_workflow`
/// already have the parsed `Value` in hand and don't need a re-parse.
pub fn extract_module_ids_from_graph_value(graph: &serde_json::Value) -> Vec<Uuid> {
    graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|nodes| {
            nodes
                .iter()
                .filter_map(|n| {
                    n.get("type")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<Uuid>().ok())
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Pure: detect whether a graph node is a `sub_workflow` system node.
///
/// Two recognized shapes (both currently emitted by different code paths):
///   * `node.kind == "sub_workflow"` (legacy)
///   * `node.type == "system:sub_workflow"` (canonical post-r228)
///
/// Returns `true` for either; downstream extractors must accept both
/// until the legacy form is purged from stored graphs.
pub fn is_sub_workflow_node(node: &serde_json::Value) -> bool {
    node.get("kind").and_then(|k| k.as_str()) == Some("sub_workflow")
        || node.get("type").and_then(|t| t.as_str()) == Some("system:sub_workflow")
}

/// Pure: collect the `sub_workflow_id` data field from every
/// `sub_workflow` system node in the graph, as raw string values.
///
/// Returns an empty `Vec` for graphs with no sub_workflow nodes or no
/// `nodes` array. Order matches `nodes[]` order.
pub fn extract_sub_workflow_id_strings(graph: &serde_json::Value) -> Vec<String> {
    graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|nodes| {
            nodes
                .iter()
                .filter(|n| is_sub_workflow_node(n))
                .filter_map(|n| {
                    n.get("data")
                        .and_then(|d| d.get("sub_workflow_id"))
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Pure: like [`extract_sub_workflow_id_strings`] but parses each id as
/// a UUID and silently drops any that don't parse. Use when downstream
/// code needs typed UUIDs (e.g. cross-workflow-stats lookups).
pub fn extract_sub_workflow_uuids(graph: &serde_json::Value) -> Vec<Uuid> {
    extract_sub_workflow_id_strings(graph)
        .into_iter()
        .filter_map(|s| s.parse::<Uuid>().ok())
        .collect()
}

/// Mutate `graph` in place: remove every edge whose `(source, target)`
/// endpoints match the supplied pair. Returns `true` iff at least one
/// edge was removed.
///
/// Replaces the duplicated `edges.retain(|e| !(src == source && tgt == target))`
/// pattern in handle_remove_edge and the `remove_edge` branch of
/// handle_update_node_config.
pub fn remove_edge_by_endpoints(graph: &mut serde_json::Value, source: &str, target: &str) -> bool {
    let Some(edges) = graph.get_mut("edges").and_then(|e| e.as_array_mut()) else {
        return false;
    };
    let before = edges.len();
    edges.retain(|e| {
        let src = e.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let tgt = e.get("target").and_then(|v| v.as_str()).unwrap_or("");
        !(src == source && tgt == target)
    });
    edges.len() < before
}

/// Mutate `graph` in place: remove every edge whose `source` or `target`
/// references `node_id`. Returns the list of removed `(source, target)`
/// endpoint pairs in their original order — callers use this for the
/// audit-trace summary in remove-node responses.
pub fn remove_edges_connected_to_node(
    graph: &mut serde_json::Value,
    node_id: &str,
) -> Vec<(String, String)> {
    let mut removed: Vec<(String, String)> = Vec::new();
    let Some(edges) = graph.get_mut("edges").and_then(|e| e.as_array_mut()) else {
        return removed;
    };
    edges.retain(|e| {
        let src = e.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let tgt = e.get("target").and_then(|v| v.as_str()).unwrap_or("");
        let connected = src == node_id || tgt == node_id;
        if connected {
            removed.push((src.to_string(), tgt.to_string()));
        }
        !connected
    });
    removed
}

/// Pure: locate a node within a workflow graph by its string `id`.
///
/// Iterates `graph.nodes[]` and returns the first entry whose `id`
/// field matches `node_id`. Returns `None` if `nodes` is missing,
/// not an array, or no entry matches.
pub fn find_node_by_id<'a>(
    graph: &'a serde_json::Value,
    node_id: &str,
) -> Option<&'a serde_json::Value> {
    graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .and_then(|nodes| {
            nodes
                .iter()
                .find(|n| n.get("id").and_then(|v| v.as_str()) == Some(node_id))
        })
}

/// Pure: true iff `graph.nodes[]` contains a node with the given `id`.
///
/// Equivalent to `find_node_by_id(graph, id).is_some()` but reads
/// nicer at sites that only need the boolean check (e.g. validating
/// that a new node id is unique before insertion).
pub fn graph_contains_node_id(graph: &serde_json::Value, node_id: &str) -> bool {
    find_node_by_id(graph, node_id).is_some()
}

/// Pure: locate a node in an already-extracted node slice by string `id`.
///
/// Sibling to [`find_node_by_id`] for callers that have already pulled
/// the `nodes` array out of the graph (e.g. because they need to mutate
/// the slice, iterate twice, or count entries) and don't want to re-pay
/// the `graph.get("nodes").as_array()` lookup just to do an id match.
///
/// Returns `None` when no entry's `id` field stringifies to `node_id`.
/// Skips entries whose `id` is missing or non-string (impossible in
/// well-formed graphs but cheap to be defensive).
pub fn find_node_in_array<'a>(
    nodes: &'a [serde_json::Value],
    node_id: &str,
) -> Option<&'a serde_json::Value> {
    nodes
        .iter()
        .find(|n| n.get("id").and_then(|v| v.as_str()) == Some(node_id))
}

/// Pure: collect the `node.id` string of every node, in document order.
///
/// Returns a `Vec<String>` (owned) so callers can move into a `HashSet`,
/// `HashMap` keys, etc. without lifetime gymnastics. Skips nodes whose
/// `id` field is missing or non-string. Returns an empty Vec if `nodes`
/// is missing or not an array.
///
/// Sibling helpers:
///   * [`extract_module_ids_from_graph_value`] — `Vec<Uuid>` from `type`
///   * [`extract_node_type_strings`] — `HashSet<String>` from `type`
pub fn extract_node_id_strings(graph: &serde_json::Value) -> Vec<String> {
    graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|nodes| {
            nodes
                .iter()
                .filter_map(|n| n.get("id").and_then(|v| v.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Pure: collect the set of `node.type` strings from a workflow graph.
///
/// Iterates `graph.nodes[*].type` and collects every `as_str()` value
/// into a `HashSet<String>`. Unlike
/// [`extract_module_ids_from_graph_value`], this preserves *all* node
/// types (including `system:*` strings), which is what the
/// similarity-comparison handlers want — two workflows that both use
/// `system:judge` should overlap on that shared structural element,
/// not just on UUID-typed module nodes.
pub fn extract_node_type_strings(graph: &serde_json::Value) -> std::collections::HashSet<String> {
    graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|nodes| {
            nodes
                .iter()
                .filter_map(|n| n.get("type").and_then(|v| v.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Pure: project a `ModuleExportInfo` into the export-bundle JSON shape.
///
/// Always emits `id` / `name` / `category` / `capability_world`. Adds
/// `source_code` and `code_template` only when present (mirrors the
/// existing `handle_export_workflow` behavior so omitted fields stay
/// omitted from the bundle).
pub fn module_export_info_to_json(info: &ModuleExportInfo) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "id": info.id.to_string(),
        "name": info.name,
        "category": info.category,
        "capability_world": info.capability_world,
    });
    if let Some(src) = &info.source_code {
        obj["source_code"] = serde_json::json!(src);
    }
    if let Some(tpl) = &info.code_template {
        obj["code_template"] = serde_json::json!(tpl);
    }
    obj
}

/// Sanitize an arbitrary module name into a cargo-package-safe identifier.
///
/// Lowercases ASCII alphanumerics, replaces every other character with `-`,
/// and trims leading/trailing dashes. Used at workflow-import time to
/// derive a `cargo new` package name from the bundle module's display name.
/// The result may be empty (e.g. when the input is `"!!!"`); callers
/// should fall back to a default in that case.
pub fn sanitize_module_cargo_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

/// Bundle-module metadata extracted from an `import_workflow` bundle entry.
///
/// `source` is the source code (`source_code` or legacy `code_template`),
/// `mod_name` is the display name (defaults to `"imported-module"`),
/// `cap_world` is the requested capability world (defaults to `"minimal-node"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleModuleMetadata<'a> {
    pub source: Option<&'a str>,
    pub mod_name: &'a str,
    pub cap_world: &'a str,
}

/// Pure: parse a bundle's per-module entry into the three fields the
/// import handler needs. The fallback chain matches the handler's
/// historical behavior:
///   * `source_code` → fallback `code_template` → `None`
///   * `name` → `"imported-module"`
///   * `capability_world` → `"minimal-node"`
pub fn extract_bundle_module_metadata(bundle_mod: &serde_json::Value) -> BundleModuleMetadata<'_> {
    let source = bundle_mod
        .get("source_code")
        .and_then(|v| v.as_str())
        .or_else(|| bundle_mod.get("code_template").and_then(|v| v.as_str()));
    let mod_name = bundle_mod
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("imported-module");
    let cap_world = bundle_mod
        .get("capability_world")
        .and_then(|v| v.as_str())
        .unwrap_or("minimal-node");
    BundleModuleMetadata {
        source,
        mod_name,
        cap_world,
    }
}

/// Compute an ILIKE-fallback match score for a candidate row given a list of
/// `%word%`-pattern search words. Score weights:
///   * name contains the word → +3
///   * description contains the word → +2
///   * any capability contains the word → +2
///   * intent JSON contains the word → +1
///
/// `words` is the same shape the handler builds:
/// `format!("%{}%", escape_like(&w.to_lowercase()))` — the `%` markers are
/// trimmed before substring matching.
pub fn compute_keyword_match_score(
    name: &str,
    description: Option<&str>,
    capabilities: &[String],
    intent: Option<&serde_json::Value>,
    words: &[String],
) -> i32 {
    let name_lower = name.to_lowercase();
    let desc_lower = description.unwrap_or("").to_lowercase();
    let caps_str = capabilities.join(" ").to_lowercase();
    let intent_str = intent
        .map(|v| v.to_string().to_lowercase())
        .unwrap_or_default();

    let mut score = 0i32;
    for word in words {
        let w = word.trim_matches('%');
        if name_lower.contains(w) {
            score += 3;
        }
        if desc_lower.contains(w) {
            score += 2;
        }
        if caps_str.contains(w) {
            score += 2;
        }
        if intent_str.contains(w) {
            score += 1;
        }
    }
    score
}

/// Workflow row returned by `list_user_workflows_with_schedule` — flat shape
/// with the joined schedule fields inlined for downstream JSON building.
#[derive(Debug)]
pub struct WorkflowExportRow {
    pub id: Uuid,
    pub name: String,
    pub graph_json: String,
    pub is_enabled: bool,
    pub cron_expression: Option<String>,
    pub timezone: String,
    pub schedule_enabled: bool,
}

/// Pure: walk the graph JSONs of every export row and collect the set
/// of UUIDs referenced as node `type` (compiled module ids) or
/// `data.moduleId` (UI-provided module pointer).
///
/// Used by `handle_export_platform_state` to build the `module_manifest`
/// — the import path uses the manifest to remap instance-local module
/// UUIDs onto the target instance's equivalents (BUG-59). Pure over a
/// slice of [`WorkflowExportRow`]; malformed graph JSONs are skipped
/// silently rather than failing the export.
///
/// Order is non-deterministic (HashSet → Vec) — callers that need a
/// stable order should sort.
pub fn collect_referenced_module_uuids(rows: &[WorkflowExportRow]) -> Vec<Uuid> {
    let mut referenced: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
    for w in rows {
        let Ok(graph) = serde_json::from_str::<serde_json::Value>(&w.graph_json) else {
            continue;
        };
        let Some(nodes) = graph.get("nodes").and_then(|v| v.as_array()) else {
            continue;
        };
        for node in nodes {
            // node.type — compiled module reference (ignores "system:*" labels
            // that can't parse as UUID).
            if let Some(s) = node.get("type").and_then(|v| v.as_str()) {
                if let Ok(uid) = Uuid::parse_str(s) {
                    referenced.insert(uid);
                }
            }
            // node.data.moduleId — UI-side module pointer (preferred over
            // node.type by some workflow editors).
            if let Some(mid) = node
                .get("data")
                .and_then(|d| d.get("moduleId"))
                .and_then(|v| v.as_str())
            {
                if let Ok(uid) = Uuid::parse_str(mid) {
                    referenced.insert(uid);
                }
            }
        }
    }
    referenced.into_iter().collect()
}

/// Outcome of [`remap_graph_module_uuids`] — the rewritten graph plus
/// per-call counters the import handler accumulates across workflows.
#[derive(Debug, Clone)]
pub struct GraphRemapOutcome {
    /// The graph JSON with module UUIDs rewritten in-place where a remap
    /// existed. On parse failure this is the input serialized via
    /// `Value::to_string()` — same fallback as the pre-extraction path.
    pub graph_json: String,
    /// Count of node positions whose `type` was successfully rewritten
    /// to a current-instance UUID. Does not double-count the optional
    /// `data.moduleId` rewrites — those mirror `type` and are
    /// best-effort by design.
    pub remapped_count: usize,
    /// Module names that appeared in `old_to_name` but had no entry in
    /// `name_to_new` (the target instance doesn't have that template
    /// installed). Caller surfaces these as warnings telling the
    /// operator to re-run `install_module_from_catalog`.
    pub unresolved_module_names: Vec<String>,
}

/// Pure: extract the `module_manifest` section from an import payload as a
/// `old_uuid → module_name` map.
///
/// Counterpart to the export-side `module_manifest` written by
/// `handle_export_platform_state`. Tolerates missing or malformed sections
/// (returns empty map) — the caller treats an empty map as "no remap
/// needed". Manifest entries without a `name` field are skipped silently.
pub fn extract_old_uuid_to_name_from_manifest(
    manifest: &serde_json::Value,
) -> std::collections::HashMap<String, String> {
    manifest
        .get("module_manifest")
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(uuid_str, entry)| {
                    let name = entry.get("name").and_then(|v| v.as_str())?.to_string();
                    Some((uuid_str.clone(), name))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Pure: collapse a list of current-instance template rows (id, name,
/// user_id) into a `name → id` lookup, keeping the FIRST insertion per
/// name. Callers MUST pass rows pre-ordered with user-installed
/// templates first (`ORDER BY user_id IS NULL ASC`) so that user-
/// installed templates win over system fallbacks for any name collision.
///
/// Used by [`handle_import_platform_state`] to build the target side of
/// the BUG-59 UUID remap. The `Option<Uuid>` user_id slot is ignored —
/// the ordering invariant lives in the SQL, not this fn.
pub fn build_name_to_new_uuid_map(
    rows: Vec<(Uuid, String, Option<Uuid>)>,
) -> std::collections::HashMap<String, Uuid> {
    let mut map: std::collections::HashMap<String, Uuid> = std::collections::HashMap::new();
    for (id, name, _user_id) in rows {
        map.entry(name).or_insert(id);
    }
    map
}

/// Parsed schedule fields from a manifest workflow entry. Borrows from
/// the input — caller passes these directly to the upsert call.
#[derive(Debug, Clone)]
pub struct ImportedSchedule<'a> {
    pub cron_expression: &'a str,
    pub timezone: &'a str,
    pub is_enabled: bool,
}

/// Pure: parse a manifest workflow's `schedule` field into the typed
/// fields needed by `upsert_workflow_schedule`.
///
/// Returns:
/// * `Some(...)` when `cron_expression` is present and non-empty.
/// * `None` when `cron_expression` is missing or empty — the import
///   path skips the schedule write entirely. Manifests written by the
///   export side never produce empty cron values; this branch defends
///   against hand-crafted manifests with the schedule object present
///   but the cron field stripped.
///
/// Defaults: `timezone` → `"UTC"`, `is_enabled` → `true`. Both match
/// the pre-extraction handler behavior verbatim.
pub fn parse_imported_schedule(schedule: &serde_json::Value) -> Option<ImportedSchedule<'_>> {
    let cron = schedule.get("cron_expression").and_then(|v| v.as_str())?;
    if cron.is_empty() {
        return None;
    }
    let timezone = schedule
        .get("timezone")
        .and_then(|v| v.as_str())
        .unwrap_or("UTC");
    let is_enabled = schedule
        .get("is_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    Some(ImportedSchedule {
        cron_expression: cron,
        timezone,
        is_enabled,
    })
}

/// Outcome of [`preview_module_remap`] — the dry-run counterpart to
/// [`remap_graph_module_uuids`]. No graph mutation; just the resolved/
/// unresolved counts and a formatted-name list ready for the JSON-RPC
/// response.
#[derive(Debug, Clone, Default)]
pub struct ModuleRemapPreview {
    /// Number of source-instance module UUIDs that will rewrite cleanly
    /// onto a current-instance equivalent.
    pub remapped: usize,
    /// Pre-formatted "<name>' (uuid: <old_uuid>)" strings for source-
    /// instance modules with no current-instance match. The format is
    /// the public dry-run response shape — operators paste these into
    /// `install_module_from_catalog` invocations.
    pub unresolved: Vec<String>,
}

/// Pure: dry-run preview of [`remap_graph_module_uuids`] across the full
/// `module_manifest`. Walks every (old_uuid, name) entry and bins it as
/// remappable or unresolved.
pub fn preview_module_remap(
    old_to_name: &std::collections::HashMap<String, String>,
    name_to_new: &std::collections::HashMap<String, Uuid>,
) -> ModuleRemapPreview {
    let mut remapped = 0usize;
    let mut unresolved: Vec<String> = Vec::new();
    for (old_uuid, name) in old_to_name {
        if name_to_new.contains_key(name.as_str()) {
            remapped += 1;
        } else {
            unresolved.push(format!("'{}' (uuid: {})", name, old_uuid));
        }
    }
    ModuleRemapPreview {
        remapped,
        unresolved,
    }
}

/// Pure: surface dry-run-only warnings about an imported workflow array.
/// Per-entry checks: a non-empty `name` field and a present `graph_json`
/// field. The output strings match the pre-extraction handler verbatim
/// so existing operator scripts that grep dry-run warnings keep working.
pub fn preview_dry_run_workflow_warnings(workflows: &[serde_json::Value]) -> Vec<String> {
    let mut warnings = Vec::new();
    for (i, wf) in workflows.iter().enumerate() {
        let name = wf.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() {
            warnings.push(format!("Workflow at index {} has no name", i));
        }
        if wf.get("graph_json").is_none() {
            warnings.push(format!("Workflow '{}' has no graph_json", name));
        }
    }
    warnings
}

/// Pure: rewrite module UUIDs in a workflow graph from the source-instance
/// IDs (recorded in the export manifest) onto the target instance's
/// equivalents.
///
/// Inputs:
/// * `graph` — the workflow graph JSON. Mutated through a clone — the
///   caller's value is not modified.
/// * `old_to_name` — `module_manifest` from the export: old UUID string →
///   module name.
/// * `name_to_new` — current-instance lookup: module name → new UUID.
///
/// Behavior:
/// * Walks `nodes[*].type` and `nodes[*].data.moduleId`. Each is rewritten
///   when both the old → name mapping AND the name → new UUID mapping
///   exist.
/// * Counts only `type` rewrites in `remapped_count` (mirrors pre-
///   extraction handler — `data.moduleId` rewrites were not counted).
/// * Names with no current-instance match are returned in
///   `unresolved_module_names`.
/// * Empty `old_to_name` short-circuits to the input verbatim with zero
///   counts — saves a clone for instances with no module manifest at all.
///
/// Note: this is BUG-59 territory — workflows imported from another
/// instance reference UUIDs that don't exist locally. Without remap, the
/// workflow loads but every node fails at dispatch with "module not
/// found".
pub fn remap_graph_module_uuids(
    graph: &serde_json::Value,
    old_to_name: &std::collections::HashMap<String, String>,
    name_to_new: &std::collections::HashMap<String, Uuid>,
) -> GraphRemapOutcome {
    if old_to_name.is_empty() {
        return GraphRemapOutcome {
            graph_json: graph.to_string(),
            remapped_count: 0,
            unresolved_module_names: vec![],
        };
    }

    let mut remapped_count = 0usize;
    let mut unresolved: Vec<String> = Vec::new();
    let mut graph = graph.clone();

    if let Some(nodes) = graph.get_mut("nodes").and_then(|v| v.as_array_mut()) {
        for node in nodes.iter_mut() {
            // Rewrite node.type — primary module pointer; counted in
            // remapped_count.
            if let Some(type_str) = node
                .get("type")
                .and_then(|v| v.as_str())
                .map(str::to_string)
            {
                if let Some(mod_name) = old_to_name.get(&type_str) {
                    if let Some(&new_uuid) = name_to_new.get(mod_name.as_str()) {
                        node["type"] = serde_json::json!(new_uuid.to_string());
                        remapped_count += 1;
                    } else {
                        unresolved.push(mod_name.clone());
                    }
                }
            }
            // Rewrite node.data.moduleId — UI-side pointer; mirrors `type`,
            // best-effort, not counted.
            if let Some(mid) = node
                .get("data")
                .and_then(|d| d.get("moduleId"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
            {
                if let Some(mod_name) = old_to_name.get(&mid) {
                    if let Some(&new_uuid) = name_to_new.get(mod_name.as_str()) {
                        if let Some(data) = node.get_mut("data") {
                            data["moduleId"] = serde_json::json!(new_uuid.to_string());
                        }
                    }
                }
            }
        }
    }

    GraphRemapOutcome {
        graph_json: serde_json::to_string(&graph).unwrap_or_else(|_| graph.to_string()),
        remapped_count,
        unresolved_module_names: unresolved,
    }
}

/// Pure: project a [`WorkflowExportRow`] into the JSON shape used by
/// the export manifest. Schedule fields collapse into a nested object
/// when a cron expression is present; absent otherwise (matches
/// pre-extraction handler behavior — operators reading the manifest
/// can grep for `schedule` to find scheduled workflows).
pub fn project_exported_workflow(row: &WorkflowExportRow) -> serde_json::Value {
    let graph_json: serde_json::Value =
        serde_json::from_str(&row.graph_json).unwrap_or(serde_json::json!({}));
    let mut obj = serde_json::json!({
        "id": row.id.to_string(),
        "name": row.name,
        "graph_json": graph_json,
        "is_enabled": row.is_enabled,
    });
    if let Some(cron_expression) = row.cron_expression.as_ref() {
        obj["schedule"] = serde_json::json!({
            "cron_expression": cron_expression,
            "timezone": row.timezone,
            "is_enabled": row.schedule_enabled,
        });
    }
    obj
}

/// 24-hour queue stats projection returned by `get_workflow_queue_stats_24h`.
#[derive(Debug)]
pub struct WorkflowQueueStats {
    pub queued: i64,
    pub running: i64,
    pub completed: i64,
    pub failed: i64,
    pub cancelled: i64,
    pub total: i64,
    pub first_started: Option<chrono::DateTime<chrono::Utc>>,
    pub last_completed: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug)]
pub struct ScaffoldingTemplateRow {
    pub id: Uuid,
    pub name: String,
    pub category: Option<String>,
    pub description: Option<String>,
    /// True when `precompiled_wasm IS NOT NULL` — the template can run immediately.
    pub is_compiled: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkflowGraphStore impl — lets the workflow executor fetch sub-workflow
// graphs through a trait without having to know about this repository or
// its Postgres pool.
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl talos_workflow_engine_core::WorkflowGraphStore for WorkflowRepository {
    async fn get_graph(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<serde_json::Value>, talos_workflow_engine_core::BoxError> {
        // `workflows.graph_json` is stored as TEXT (per the schema), not JSONB.
        // Decoding directly into `serde_json::Value` fails with a typed-decode
        // error and the engine treats the lookup as "graph not found" — which
        // breaks every sub-workflow / capability-dispatch / judge / ensemble
        // node with a misleading "Sub-workflow workflow X not found" error
        // message even though the row exists. Decode as String and parse.
        let row: Option<(String,)> =
            sqlx::query_as("SELECT graph_json FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(workflow_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;
        match row {
            None => Ok(None),
            Some((s,)) => {
                let v = serde_json::from_str(&s).map_err(
                    |e| -> talos_workflow_engine_core::BoxError {
                        format!("graph_json parse error for {}: {}", workflow_id, e).into()
                    },
                )?;
                Ok(Some(v))
            }
        }
    }

    async fn get_graphs(
        &self,
        ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<HashMap<Uuid, serde_json::Value>, talos_workflow_engine_core::BoxError> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        // Same TEXT-not-JSONB story as `get_graph`. The batch path was the
        // primary symptom: `populate_sub_workflow_cache` swallowed the decode
        // error with a WARN and fell back to per-node `get_graph` queries —
        // which then ALSO failed with the same decode bug, so every
        // sub-workflow node returned GraphNotFound.
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, graph_json FROM workflows \
             WHERE id = ANY($1) AND user_id = $2",
        )
        .bind(ids)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for (id, s) in rows {
            match serde_json::from_str::<serde_json::Value>(&s) {
                Ok(v) => {
                    out.insert(id, v);
                }
                Err(e) => {
                    tracing::warn!(
                        workflow_id = %id,
                        error = %e,
                        "Skipping workflow with malformed graph_json — sub-workflow \
                         dispatch will see GraphNotFound for this id"
                    );
                }
            }
        }
        Ok(out)
    }

    async fn resolve_by_name(
        &self,
        name: &str,
        user_id: Uuid,
    ) -> Result<Option<Uuid>, talos_workflow_engine_core::BoxError> {
        let row: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM workflows WHERE name = $1 AND user_id = $2 LIMIT 1")
                .bind(name)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(row.map(|(id,)| id))
    }

    async fn resolve_by_capabilities(
        &self,
        required_capabilities: &[String],
        user_id: Uuid,
    ) -> Result<Option<(Uuid, String)>, talos_workflow_engine_core::BoxError> {
        let row: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT id, name FROM workflows \
             WHERE user_id = $1 AND capabilities @> $2 \
             ORDER BY updated_at DESC LIMIT 1",
        )
        .bind(user_id)
        .bind(required_capabilities)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row)
    }
}

#[cfg(test)]
mod export_helpers_tests {
    use super::*;

    fn row(graph: serde_json::Value, cron: Option<&str>) -> WorkflowExportRow {
        WorkflowExportRow {
            id: Uuid::new_v4(),
            name: "wf".into(),
            graph_json: graph.to_string(),
            is_enabled: true,
            cron_expression: cron.map(String::from),
            timezone: "UTC".into(),
            schedule_enabled: cron.is_some(),
        }
    }

    #[test]
    fn collect_uuids_picks_up_node_type_uuid() {
        let mid = Uuid::new_v4();
        let r = row(
            serde_json::json!({"nodes": [{"id": "n1", "type": mid.to_string()}]}),
            None,
        );
        let out = collect_referenced_module_uuids(&[r]);
        assert_eq!(out, vec![mid]);
    }

    #[test]
    fn collect_uuids_picks_up_data_module_id() {
        let mid = Uuid::new_v4();
        let r = row(
            serde_json::json!({
                "nodes": [{"id": "n1", "data": {"moduleId": mid.to_string()}}]
            }),
            None,
        );
        let out = collect_referenced_module_uuids(&[r]);
        assert_eq!(out, vec![mid]);
    }

    #[test]
    fn collect_uuids_skips_system_node_types() {
        let r = row(
            serde_json::json!({
                "nodes": [
                    {"id": "n1", "type": "system:judge"},
                    {"id": "n2", "type": "system:collect"},
                ]
            }),
            None,
        );
        assert!(collect_referenced_module_uuids(&[r]).is_empty());
    }

    #[test]
    fn collect_uuids_dedups_across_workflows() {
        let mid = Uuid::new_v4();
        let r1 = row(
            serde_json::json!({"nodes": [{"id": "n1", "type": mid.to_string()}]}),
            None,
        );
        let r2 = row(
            serde_json::json!({"nodes": [{"id": "n2", "type": mid.to_string()}]}),
            None,
        );
        let out = collect_referenced_module_uuids(&[r1, r2]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], mid);
    }

    #[test]
    fn collect_uuids_skips_malformed_graphs_without_failing() {
        let r1 = WorkflowExportRow {
            id: Uuid::new_v4(),
            name: "bad".into(),
            graph_json: "not json".into(),
            is_enabled: true,
            cron_expression: None,
            timezone: "UTC".into(),
            schedule_enabled: false,
        };
        let r2 = row(serde_json::json!({"nodes": "wrong-shape"}), None);
        assert!(collect_referenced_module_uuids(&[r1, r2]).is_empty());
    }

    #[test]
    fn project_exported_workflow_omits_schedule_when_no_cron() {
        let mid = Uuid::new_v4();
        let r = row(
            serde_json::json!({"nodes": [{"id": "n1", "type": mid.to_string()}]}),
            None,
        );
        let out = project_exported_workflow(&r);
        assert!(out.get("schedule").is_none(), "got: {}", out);
        assert_eq!(out["is_enabled"], serde_json::json!(true));
    }

    #[test]
    fn project_exported_workflow_includes_schedule_when_cron_set() {
        let r = row(serde_json::json!({"nodes": []}), Some("0 0 * * *"));
        let out = project_exported_workflow(&r);
        let schedule = out.get("schedule").expect("schedule field");
        assert_eq!(schedule["cron_expression"], serde_json::json!("0 0 * * *"));
        assert_eq!(schedule["timezone"], serde_json::json!("UTC"));
        assert_eq!(schedule["is_enabled"], serde_json::json!(true));
    }

    #[test]
    fn project_exported_workflow_handles_malformed_graph_gracefully() {
        let r = WorkflowExportRow {
            id: Uuid::new_v4(),
            name: "bad".into(),
            graph_json: "not json".into(),
            is_enabled: false,
            cron_expression: None,
            timezone: "UTC".into(),
            schedule_enabled: false,
        };
        let out = project_exported_workflow(&r);
        // graph_json defaults to {} on parse failure — same behavior as
        // pre-extraction inline code.
        assert_eq!(out["graph_json"], serde_json::json!({}));
        assert_eq!(out["is_enabled"], serde_json::json!(false));
    }

    // ── remap_graph_module_uuids tests ────────────────────────────────────

    #[test]
    fn remap_short_circuits_when_manifest_empty() {
        let graph = serde_json::json!({
            "nodes": [{"id": "n1", "type": Uuid::new_v4().to_string()}]
        });
        let out = remap_graph_module_uuids(&graph, &HashMap::new(), &HashMap::new());
        assert_eq!(out.remapped_count, 0);
        assert!(out.unresolved_module_names.is_empty());
        // Pre-extraction behavior: empty manifest returns input verbatim.
        assert_eq!(out.graph_json, graph.to_string());
    }

    #[test]
    fn remap_rewrites_node_type_when_both_maps_have_match() {
        let old_id = Uuid::new_v4();
        let new_id = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [{"id": "n1", "type": old_id.to_string()}]
        });
        let old_to_name = HashMap::from([(old_id.to_string(), "slack".to_string())]);
        let name_to_new = HashMap::from([("slack".to_string(), new_id)]);
        let out = remap_graph_module_uuids(&graph, &old_to_name, &name_to_new);
        assert_eq!(out.remapped_count, 1);
        assert!(out.unresolved_module_names.is_empty());
        // The rewritten graph carries the new UUID.
        let rewritten: serde_json::Value = serde_json::from_str(&out.graph_json).unwrap();
        assert_eq!(
            rewritten["nodes"][0]["type"],
            serde_json::json!(new_id.to_string())
        );
    }

    #[test]
    fn remap_records_unresolved_when_target_lacks_install() {
        let old_id = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [{"id": "n1", "type": old_id.to_string()}]
        });
        let old_to_name = HashMap::from([(old_id.to_string(), "missing-module".to_string())]);
        let name_to_new: HashMap<String, Uuid> = HashMap::new();
        let out = remap_graph_module_uuids(&graph, &old_to_name, &name_to_new);
        assert_eq!(out.remapped_count, 0);
        assert_eq!(
            out.unresolved_module_names,
            vec!["missing-module".to_string()]
        );
        // Source UUID is preserved when no target — caller surfaces a warning.
        let rewritten: serde_json::Value = serde_json::from_str(&out.graph_json).unwrap();
        assert_eq!(
            rewritten["nodes"][0]["type"],
            serde_json::json!(old_id.to_string())
        );
    }

    #[test]
    fn remap_rewrites_data_module_id_without_double_count() {
        let old_id = Uuid::new_v4();
        let new_id = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [{
                "id": "n1",
                "type": old_id.to_string(),
                "data": {"moduleId": old_id.to_string()}
            }]
        });
        let old_to_name = HashMap::from([(old_id.to_string(), "slack".to_string())]);
        let name_to_new = HashMap::from([("slack".to_string(), new_id)]);
        let out = remap_graph_module_uuids(&graph, &old_to_name, &name_to_new);
        // remapped_count counts only `type`, not data.moduleId — matches
        // pre-extraction behavior.
        assert_eq!(out.remapped_count, 1);
        let rewritten: serde_json::Value = serde_json::from_str(&out.graph_json).unwrap();
        assert_eq!(
            rewritten["nodes"][0]["type"],
            serde_json::json!(new_id.to_string())
        );
        assert_eq!(
            rewritten["nodes"][0]["data"]["moduleId"],
            serde_json::json!(new_id.to_string())
        );
    }

    #[test]
    fn remap_preserves_unrelated_node_keys() {
        let old_id = Uuid::new_v4();
        let new_id = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [{
                "id": "n1",
                "type": old_id.to_string(),
                "label": "Custom label",
                "data": {"moduleId": old_id.to_string(), "config": {"k": "v"}}
            }],
            "edges": [{"from": "n1", "to": "n2"}]
        });
        let old_to_name = HashMap::from([(old_id.to_string(), "slack".to_string())]);
        let name_to_new = HashMap::from([("slack".to_string(), new_id)]);
        let out = remap_graph_module_uuids(&graph, &old_to_name, &name_to_new);
        let rewritten: serde_json::Value = serde_json::from_str(&out.graph_json).unwrap();
        // Non-touched fields preserved verbatim.
        assert_eq!(
            rewritten["nodes"][0]["label"],
            serde_json::json!("Custom label")
        );
        assert_eq!(
            rewritten["nodes"][0]["data"]["config"],
            serde_json::json!({"k": "v"})
        );
        assert_eq!(rewritten["edges"][0]["from"], serde_json::json!("n1"));
    }

    // ── extract_old_uuid_to_name_from_manifest tests ─────────────────────

    #[test]
    fn extract_uuid_name_returns_empty_when_section_missing() {
        let manifest = serde_json::json!({"workflows": []});
        assert!(extract_old_uuid_to_name_from_manifest(&manifest).is_empty());
    }

    #[test]
    fn extract_uuid_name_skips_entries_without_name() {
        let id1 = Uuid::new_v4().to_string();
        let id2 = Uuid::new_v4().to_string();
        let manifest = serde_json::json!({
            "module_manifest": {
                id1.clone(): {"name": "slack", "source": "template"},
                id2.clone(): {"source": "template"}, // no name → skipped
            }
        });
        let out = extract_old_uuid_to_name_from_manifest(&manifest);
        assert_eq!(out.get(&id1), Some(&"slack".to_string()));
        assert!(!out.contains_key(&id2));
    }

    #[test]
    fn extract_uuid_name_returns_empty_when_section_not_object() {
        let manifest = serde_json::json!({"module_manifest": "not-an-object"});
        assert!(extract_old_uuid_to_name_from_manifest(&manifest).is_empty());
    }

    // ── build_name_to_new_uuid_map tests ──────────────────────────────────

    #[test]
    fn build_name_uuid_map_first_insertion_wins() {
        // Caller ordering: user-installed first (Some(user_id)), system
        // fallback second (None). build_* keeps the first.
        let user_id = Uuid::new_v4();
        let user_template = Uuid::new_v4();
        let system_template = Uuid::new_v4();
        let rows = vec![
            (user_template, "slack".to_string(), Some(user_id)),
            (system_template, "slack".to_string(), None),
        ];
        let out = build_name_to_new_uuid_map(rows);
        assert_eq!(out.get("slack"), Some(&user_template));
    }

    #[test]
    fn build_name_uuid_map_handles_distinct_names() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let rows = vec![
            (id1, "slack".to_string(), None),
            (id2, "http".to_string(), None),
        ];
        let out = build_name_to_new_uuid_map(rows);
        assert_eq!(out.len(), 2);
        assert_eq!(out["slack"], id1);
        assert_eq!(out["http"], id2);
    }

    #[test]
    fn build_name_uuid_map_empty_input() {
        assert!(build_name_to_new_uuid_map(vec![]).is_empty());
    }

    // ── preview_dry_run_workflow_warnings tests ────────────────────────────

    #[test]
    fn dry_run_warnings_flags_missing_name_with_index() {
        let workflows = vec![
            serde_json::json!({"name": "ok", "graph_json": {}}),
            serde_json::json!({"graph_json": {}}),
        ];
        let warnings = preview_dry_run_workflow_warnings(&workflows);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("index 1"));
    }

    #[test]
    fn dry_run_warnings_flags_missing_graph_json() {
        let workflows = vec![serde_json::json!({"name": "MyFlow"})];
        let warnings = preview_dry_run_workflow_warnings(&workflows);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("'MyFlow'"));
        assert!(warnings[0].contains("graph_json"));
    }

    #[test]
    fn dry_run_warnings_clean_input_yields_no_warnings() {
        let workflows = vec![
            serde_json::json!({"name": "a", "graph_json": {}}),
            serde_json::json!({"name": "b", "graph_json": {"nodes": []}}),
        ];
        assert!(preview_dry_run_workflow_warnings(&workflows).is_empty());
    }

    // ── preview_module_remap tests ─────────────────────────────────────────

    #[test]
    fn preview_remap_counts_resolvable_and_lists_unresolvable() {
        let id1 = Uuid::new_v4().to_string();
        let id2 = Uuid::new_v4().to_string();
        let new_id = Uuid::new_v4();
        let old_to_name = HashMap::from([
            (id1.clone(), "slack".to_string()),
            (id2.clone(), "missing".to_string()),
        ]);
        let name_to_new = HashMap::from([("slack".to_string(), new_id)]);
        let preview = preview_module_remap(&old_to_name, &name_to_new);
        assert_eq!(preview.remapped, 1);
        assert_eq!(preview.unresolved.len(), 1);
        assert!(preview.unresolved[0].contains("'missing'"));
        assert!(preview.unresolved[0].contains(&id2));
    }

    #[test]
    fn preview_remap_empty_inputs() {
        let p = preview_module_remap(&HashMap::new(), &HashMap::new());
        assert_eq!(p.remapped, 0);
        assert!(p.unresolved.is_empty());
    }

    // ── parse_imported_schedule tests ──────────────────────────────────────

    #[test]
    fn parse_schedule_returns_none_when_cron_missing() {
        let schedule = serde_json::json!({"timezone": "UTC", "is_enabled": true});
        assert!(parse_imported_schedule(&schedule).is_none());
    }

    #[test]
    fn parse_schedule_returns_none_when_cron_empty() {
        let schedule = serde_json::json!({"cron_expression": "", "timezone": "UTC"});
        assert!(parse_imported_schedule(&schedule).is_none());
    }

    #[test]
    fn parse_schedule_uses_default_timezone_and_enabled() {
        let schedule = serde_json::json!({"cron_expression": "0 0 * * *"});
        let parsed = parse_imported_schedule(&schedule).expect("parsed");
        assert_eq!(parsed.cron_expression, "0 0 * * *");
        assert_eq!(parsed.timezone, "UTC");
        assert!(parsed.is_enabled);
    }

    #[test]
    fn parse_schedule_honors_explicit_disabled_flag() {
        let schedule = serde_json::json!({"cron_expression": "*/5 * * * *", "is_enabled": false});
        let parsed = parse_imported_schedule(&schedule).expect("parsed");
        assert!(!parsed.is_enabled);
    }

    #[test]
    fn parse_schedule_passes_through_explicit_timezone() {
        let schedule = serde_json::json!({
            "cron_expression": "0 12 * * *",
            "timezone": "America/Los_Angeles",
        });
        let parsed = parse_imported_schedule(&schedule).expect("parsed");
        assert_eq!(parsed.timezone, "America/Los_Angeles");
    }

    #[test]
    fn remap_handles_unknown_old_uuid_in_graph_silently() {
        // Node references an old UUID that's NOT in old_to_name (orphan).
        // Pre-extraction behavior: pass through, no warning.
        let orphan_id = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [{"id": "n1", "type": orphan_id.to_string()}]
        });
        let old_to_name = HashMap::from([(Uuid::new_v4().to_string(), "other".to_string())]);
        let name_to_new = HashMap::from([("other".to_string(), Uuid::new_v4())]);
        let out = remap_graph_module_uuids(&graph, &old_to_name, &name_to_new);
        assert_eq!(out.remapped_count, 0);
        assert!(out.unresolved_module_names.is_empty());
    }

    // -- format_pgvector_literal --

    #[test]
    fn pgvector_literal_empty() {
        assert_eq!(format_pgvector_literal(&[]), "[]");
    }

    #[test]
    fn pgvector_literal_round_trip() {
        let s = format_pgvector_literal(&[0.1, -0.2, 1.0]);
        assert_eq!(s, "[0.1,-0.2,1]");
    }

    // -- compute_keyword_match_score --

    fn pat(w: &str) -> String {
        format!("%{}%", w)
    }

    #[test]
    fn score_name_match_weighted_3() {
        let words = vec![pat("foo")];
        let s = compute_keyword_match_score("FooBar", None, &[], None, &words);
        assert_eq!(s, 3);
    }

    #[test]
    fn score_description_weighted_2() {
        let words = vec![pat("alpha")];
        let s = compute_keyword_match_score("x", Some("contains alpha here"), &[], None, &words);
        assert_eq!(s, 2);
    }

    #[test]
    fn score_capability_weighted_2() {
        let words = vec![pat("http")];
        let caps = vec!["HTTP_FETCH".to_string(), "redis".to_string()];
        let s = compute_keyword_match_score("x", None, &caps, None, &words);
        assert_eq!(s, 2);
    }

    #[test]
    fn score_intent_weighted_1() {
        let words = vec![pat("search")];
        let intent = serde_json::json!({"goal": "user search query"});
        let s = compute_keyword_match_score("x", None, &[], Some(&intent), &words);
        assert_eq!(s, 1);
    }

    #[test]
    fn score_aggregates_all_fields_and_words() {
        // Two words, both hitting name (+3) and description (+2) → 10.
        let words = vec![pat("alpha"), pat("beta")];
        let s = compute_keyword_match_score(
            "alpha and beta",
            Some("alpha-beta soup"),
            &[],
            None,
            &words,
        );
        assert_eq!(s, 10);
    }

    #[test]
    fn score_no_match_zero() {
        let words = vec![pat("missing")];
        let s = compute_keyword_match_score("foo", Some("bar"), &[], None, &words);
        assert_eq!(s, 0);
    }

    #[test]
    fn score_case_insensitive() {
        // Lowercased words searching uppercased fields still match.
        let words = vec![pat("foo")];
        let s = compute_keyword_match_score("FOO", Some("FOO BAR"), &[], None, &words);
        assert_eq!(s, 5);
    }

    #[test]
    fn score_strips_outer_percent_markers() {
        // Patterns from the handler arrive wrapped in `%`; the helper trims them.
        let words = vec!["%foo%".to_string()];
        let s = compute_keyword_match_score("foo", None, &[], None, &words);
        assert_eq!(s, 3);
    }

    // -- sanitize_module_cargo_name --

    #[test]
    fn cargo_name_lowercases_alphanumerics() {
        assert_eq!(sanitize_module_cargo_name("FooBar2"), "foobar2");
    }

    #[test]
    fn cargo_name_replaces_specials_with_dash() {
        assert_eq!(
            sanitize_module_cargo_name("My Cool/Module v1.0"),
            "my-cool-module-v1-0"
        );
    }

    #[test]
    fn cargo_name_trims_leading_trailing_dashes() {
        assert_eq!(sanitize_module_cargo_name("!!foo!!"), "foo");
    }

    #[test]
    fn cargo_name_empty_when_all_specials() {
        assert_eq!(sanitize_module_cargo_name("!!!"), "");
    }

    // -- extract_bundle_module_metadata --

    #[test]
    fn bundle_meta_full_fields() {
        let v = serde_json::json!({
            "source_code": "fn main() {}",
            "name": "MyMod",
            "capability_world": "http-node",
        });
        let m = extract_bundle_module_metadata(&v);
        assert_eq!(m.source, Some("fn main() {}"));
        assert_eq!(m.mod_name, "MyMod");
        assert_eq!(m.cap_world, "http-node");
    }

    #[test]
    fn bundle_meta_falls_back_to_code_template() {
        let v = serde_json::json!({
            "code_template": "fn main() {}",
        });
        let m = extract_bundle_module_metadata(&v);
        assert_eq!(m.source, Some("fn main() {}"));
    }

    #[test]
    fn bundle_meta_source_code_wins_over_code_template() {
        let v = serde_json::json!({
            "source_code": "primary",
            "code_template": "secondary",
        });
        let m = extract_bundle_module_metadata(&v);
        assert_eq!(m.source, Some("primary"));
    }

    #[test]
    fn bundle_meta_defaults_when_missing() {
        let v = serde_json::json!({});
        let m = extract_bundle_module_metadata(&v);
        assert_eq!(m.source, None);
        assert_eq!(m.mod_name, "imported-module");
        assert_eq!(m.cap_world, "minimal-node");
    }

    // -- extract_module_ids_from_graph_value --

    #[test]
    fn graph_value_extracts_uuid_typed_nodes() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [
                {"id": "n1", "type": id1.to_string()},
                {"id": "n2", "type": id2.to_string()},
            ]
        });
        let out = extract_module_ids_from_graph_value(&graph);
        assert_eq!(out, vec![id1, id2]);
    }

    #[test]
    fn graph_value_skips_non_uuid_types() {
        let id = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [
                {"id": "n0", "type": "system:approval"},
                {"id": "n1", "type": id.to_string()},
                {"id": "n2", "type": "not-a-uuid"},
            ]
        });
        let out = extract_module_ids_from_graph_value(&graph);
        assert_eq!(out, vec![id]);
    }

    #[test]
    fn graph_value_empty_when_no_nodes() {
        let graph = serde_json::json!({});
        assert!(extract_module_ids_from_graph_value(&graph).is_empty());
    }

    // -- module_export_info_to_json --

    fn export_info(with_src: bool, with_tpl: bool, cap: Option<&str>) -> ModuleExportInfo {
        ModuleExportInfo {
            id: Uuid::nil(),
            name: "MyMod".into(),
            category: "core".into(),
            capability_world: cap.map(|s| s.to_string()),
            source_code: with_src.then(|| "fn main() {}".to_string()),
            code_template: with_tpl.then(|| "TEMPLATE".to_string()),
        }
    }

    #[test]
    fn export_json_emits_required_fields() {
        let info = export_info(false, false, Some("http-node"));
        let v = module_export_info_to_json(&info);
        assert_eq!(
            v.get("id").and_then(|s| s.as_str()),
            Some(Uuid::nil().to_string().as_str())
        );
        assert_eq!(v.get("name").and_then(|s| s.as_str()), Some("MyMod"));
        assert_eq!(v.get("category").and_then(|s| s.as_str()), Some("core"));
        assert_eq!(
            v.get("capability_world").and_then(|s| s.as_str()),
            Some("http-node")
        );
        assert!(v.get("source_code").is_none());
        assert!(v.get("code_template").is_none());
    }

    #[test]
    fn export_json_includes_source_when_present() {
        let info = export_info(true, false, None);
        let v = module_export_info_to_json(&info);
        assert_eq!(
            v.get("source_code").and_then(|s| s.as_str()),
            Some("fn main() {}")
        );
        assert!(v.get("code_template").is_none());
    }

    #[test]
    fn export_json_includes_both_source_and_template() {
        let info = export_info(true, true, Some("minimal-node"));
        let v = module_export_info_to_json(&info);
        assert!(v.get("source_code").is_some());
        assert!(v.get("code_template").is_some());
    }

    // -- extract_node_type_strings --

    #[test]
    fn node_type_strings_collects_all_types() {
        let id = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [
                {"id": "n1", "type": id.to_string()},
                {"id": "n2", "type": "system:judge"},
                {"id": "n3", "type": "system:collect"},
            ]
        });
        let out = extract_node_type_strings(&graph);
        assert!(out.contains(&id.to_string()));
        assert!(out.contains("system:judge"));
        assert!(out.contains("system:collect"));
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn node_type_strings_dedupes_repeated_types() {
        let graph = serde_json::json!({
            "nodes": [
                {"id": "a", "type": "system:judge"},
                {"id": "b", "type": "system:judge"},
                {"id": "c", "type": "system:judge"},
            ]
        });
        let out = extract_node_type_strings(&graph);
        assert_eq!(out.len(), 1);
        assert!(out.contains("system:judge"));
    }

    #[test]
    fn node_type_strings_empty_when_no_nodes() {
        let graph = serde_json::json!({});
        assert!(extract_node_type_strings(&graph).is_empty());
    }

    #[test]
    fn node_type_strings_skips_non_string_type() {
        let graph = serde_json::json!({
            "nodes": [
                {"id": "a", "type": null},
                {"id": "b"}, // missing type
                {"id": "c", "type": "system:judge"},
            ]
        });
        let out = extract_node_type_strings(&graph);
        assert_eq!(out.len(), 1);
        assert!(out.contains("system:judge"));
    }

    // -- WorkflowExecStats helpers --

    fn stats(total: i64, succeeded: i64, avg: Option<f64>) -> WorkflowExecStats {
        WorkflowExecStats {
            total,
            succeeded,
            failed: total - succeeded,
            running: 0,
            avg_duration_secs: avg,
        }
    }

    #[test]
    fn exec_stats_empty_zeroes_all_fields() {
        let s = WorkflowExecStats::empty();
        assert_eq!(s.total, 0);
        assert_eq!(s.succeeded, 0);
        assert_eq!(s.failed, 0);
        assert_eq!(s.running, 0);
        assert_eq!(s.avg_duration_secs, None);
    }

    #[test]
    fn success_rate_zero_when_no_runs() {
        assert_eq!(WorkflowExecStats::empty().success_rate_percent(), 0.0);
    }

    #[test]
    fn success_rate_full_when_all_succeed() {
        assert_eq!(stats(10, 10, None).success_rate_percent(), 100.0);
    }

    #[test]
    fn success_rate_proportional() {
        assert_eq!(stats(4, 1, None).success_rate_percent(), 25.0);
        assert_eq!(stats(8, 2, None).success_rate_percent(), 25.0);
    }

    #[test]
    fn stats_to_json_emits_canonical_shape() {
        let v = stats(10, 7, Some(1.5)).to_json(30);
        assert_eq!(v.get("period_days").and_then(|x| x.as_i64()), Some(30));
        assert_eq!(v.get("total_executions").and_then(|x| x.as_i64()), Some(10));
        assert_eq!(v.get("succeeded").and_then(|x| x.as_i64()), Some(7));
        assert_eq!(v.get("failed").and_then(|x| x.as_i64()), Some(3));
        // MCP-19: success_rate_percent emits a JSON number, not a string.
        assert_eq!(
            v.get("success_rate_percent").and_then(|x| x.as_f64()),
            Some(70.0)
        );
        assert_eq!(
            v.get("avg_duration_secs").and_then(|x| x.as_f64()),
            Some(1.5)
        );
    }

    #[test]
    fn stats_to_json_handles_zero_total() {
        let v = WorkflowExecStats::empty().to_json(7);
        assert_eq!(v.get("total_executions").and_then(|x| x.as_i64()), Some(0));
        // MCP-19: numeric output, not string.
        assert_eq!(
            v.get("success_rate_percent").and_then(|x| x.as_f64()),
            Some(0.0)
        );
        assert!(v
            .get("avg_duration_secs")
            .map(|x| x.is_null())
            .unwrap_or(false));
    }

    // -- find_node_by_id / graph_contains_node_id --

    #[test]
    fn finds_node_by_string_id() {
        let graph = serde_json::json!({
            "nodes": [
                {"id": "n1", "type": "minimal"},
                {"id": "n2", "type": "http"},
            ]
        });
        let node = find_node_by_id(&graph, "n2").unwrap();
        assert_eq!(node.get("type").and_then(|v| v.as_str()), Some("http"));
    }

    #[test]
    fn find_returns_none_when_id_absent() {
        let graph = serde_json::json!({
            "nodes": [{"id": "n1"}]
        });
        assert!(find_node_by_id(&graph, "missing").is_none());
    }

    #[test]
    fn find_returns_none_when_no_nodes_field() {
        let graph = serde_json::json!({"edges": []});
        assert!(find_node_by_id(&graph, "anything").is_none());
    }

    #[test]
    fn find_skips_node_without_string_id() {
        let graph = serde_json::json!({
            "nodes": [
                {"id": 42},          // numeric id — not a string
                {"id": "real"},
            ]
        });
        // Numeric ids aren't strings — non-matching, then matches "real".
        assert!(find_node_by_id(&graph, "real").is_some());
        assert!(find_node_by_id(&graph, "42").is_none());
    }

    #[test]
    fn graph_contains_matches_find_existence() {
        let graph = serde_json::json!({
            "nodes": [{"id": "first"}]
        });
        assert!(graph_contains_node_id(&graph, "first"));
        assert!(!graph_contains_node_id(&graph, "second"));
    }

    // -- find_node_in_array --

    #[test]
    fn find_node_in_array_matches_first_id() {
        let nodes = vec![
            serde_json::json!({"id": "a", "kind": "src"}),
            serde_json::json!({"id": "b", "kind": "tgt"}),
        ];
        let n = find_node_in_array(&nodes, "b").unwrap();
        assert_eq!(n.get("kind").and_then(|v| v.as_str()), Some("tgt"));
    }

    #[test]
    fn find_node_in_array_returns_none_on_miss() {
        let nodes = vec![serde_json::json!({"id": "only"})];
        assert!(find_node_in_array(&nodes, "missing").is_none());
    }

    #[test]
    fn find_node_in_array_skips_non_string_ids() {
        let nodes = vec![
            serde_json::json!({"id": 42}),
            serde_json::json!({"id": null}),
            serde_json::json!({"id": "real"}),
        ];
        assert!(find_node_in_array(&nodes, "real").is_some());
        assert!(find_node_in_array(&nodes, "42").is_none());
    }

    #[test]
    fn find_node_in_array_empty_slice_is_none() {
        let nodes: Vec<serde_json::Value> = Vec::new();
        assert!(find_node_in_array(&nodes, "anything").is_none());
    }

    // -- remove_edge_by_endpoints --

    #[test]
    fn remove_edge_by_endpoints_drops_match() {
        let mut graph = serde_json::json!({
            "edges": [
                {"source": "a", "target": "b"},
                {"source": "b", "target": "c"},
            ]
        });
        let removed = remove_edge_by_endpoints(&mut graph, "a", "b");
        assert!(removed);
        let edges = graph.get("edges").unwrap().as_array().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].get("source").and_then(|v| v.as_str()), Some("b"));
    }

    #[test]
    fn remove_edge_by_endpoints_no_match_returns_false() {
        let mut graph = serde_json::json!({
            "edges": [{"source": "a", "target": "b"}]
        });
        let removed = remove_edge_by_endpoints(&mut graph, "x", "y");
        assert!(!removed);
        assert_eq!(graph.get("edges").unwrap().as_array().unwrap().len(), 1);
    }

    #[test]
    fn remove_edge_by_endpoints_handles_missing_edges_field() {
        let mut graph = serde_json::json!({"nodes": []});
        assert!(!remove_edge_by_endpoints(&mut graph, "a", "b"));
    }

    #[test]
    fn remove_edge_by_endpoints_only_drops_exact_pair() {
        // (a,b) must match BOTH source and target — partial matches stay.
        let mut graph = serde_json::json!({
            "edges": [
                {"source": "a", "target": "x"},  // wrong target
                {"source": "y", "target": "b"},  // wrong source
                {"source": "a", "target": "b"},  // exact match
            ]
        });
        assert!(remove_edge_by_endpoints(&mut graph, "a", "b"));
        assert_eq!(graph.get("edges").unwrap().as_array().unwrap().len(), 2);
    }

    // -- remove_edges_connected_to_node --

    #[test]
    fn remove_edges_connected_to_node_strips_in_and_out() {
        let mut graph = serde_json::json!({
            "edges": [
                {"source": "a", "target": "b"},  // outgoing
                {"source": "b", "target": "c"},  // outgoing
                {"source": "x", "target": "a"},  // incoming
                {"source": "y", "target": "z"},  // unrelated
            ]
        });
        let removed = remove_edges_connected_to_node(&mut graph, "a");
        assert_eq!(removed.len(), 2);
        assert!(removed.contains(&("a".to_string(), "b".to_string())));
        assert!(removed.contains(&("x".to_string(), "a".to_string())));
        let remaining = graph.get("edges").unwrap().as_array().unwrap();
        assert_eq!(remaining.len(), 2);
    }

    #[test]
    fn remove_edges_connected_to_node_empty_when_no_match() {
        let mut graph = serde_json::json!({
            "edges": [
                {"source": "x", "target": "y"},
            ]
        });
        let removed = remove_edges_connected_to_node(&mut graph, "missing");
        assert!(removed.is_empty());
    }

    #[test]
    fn remove_edges_connected_to_node_handles_missing_edges_field() {
        let mut graph = serde_json::json!({"nodes": []});
        assert!(remove_edges_connected_to_node(&mut graph, "a").is_empty());
    }

    // -- is_sub_workflow_node --

    #[test]
    fn is_sub_workflow_matches_canonical_type() {
        let n = serde_json::json!({"type": "system:sub_workflow"});
        assert!(is_sub_workflow_node(&n));
    }

    #[test]
    fn is_sub_workflow_matches_legacy_kind() {
        let n = serde_json::json!({"kind": "sub_workflow"});
        assert!(is_sub_workflow_node(&n));
    }

    #[test]
    fn is_sub_workflow_rejects_other_system_nodes() {
        let n = serde_json::json!({"type": "system:judge"});
        assert!(!is_sub_workflow_node(&n));
    }

    #[test]
    fn is_sub_workflow_rejects_module_node() {
        let n = serde_json::json!({"type": "550e8400-e29b-41d4-a716-446655440000"});
        assert!(!is_sub_workflow_node(&n));
    }

    // -- extract_sub_workflow_id_strings / _uuids --

    #[test]
    fn extracts_id_string_from_data_field() {
        let id = Uuid::new_v4().to_string();
        let graph = serde_json::json!({
            "nodes": [
                {"type": "system:sub_workflow", "data": {"sub_workflow_id": id.clone()}},
                {"type": "system:judge"},
            ]
        });
        let out = extract_sub_workflow_id_strings(&graph);
        assert_eq!(out, vec![id]);
    }

    #[test]
    fn extracts_uuids_filters_unparseable() {
        let valid = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [
                {"type": "system:sub_workflow", "data": {"sub_workflow_id": valid.to_string()}},
                {"type": "system:sub_workflow", "data": {"sub_workflow_id": "not-a-uuid"}},
            ]
        });
        let out = extract_sub_workflow_uuids(&graph);
        assert_eq!(out, vec![valid]);
    }

    #[test]
    fn extracts_empty_when_no_sub_workflow_nodes() {
        let graph = serde_json::json!({
            "nodes": [{"type": "system:judge"}, {"type": "system:collect"}]
        });
        assert!(extract_sub_workflow_id_strings(&graph).is_empty());
    }

    #[test]
    fn extracts_handles_legacy_kind_too() {
        let id = Uuid::new_v4().to_string();
        let graph = serde_json::json!({
            "nodes": [
                {"kind": "sub_workflow", "data": {"sub_workflow_id": id.clone()}},
            ]
        });
        let out = extract_sub_workflow_id_strings(&graph);
        assert_eq!(out, vec![id]);
    }

    #[test]
    fn extracts_skips_nodes_missing_data_field() {
        // Sub-workflow node without a data.sub_workflow_id: silently dropped.
        let graph = serde_json::json!({
            "nodes": [{"type": "system:sub_workflow"}]
        });
        assert!(extract_sub_workflow_id_strings(&graph).is_empty());
    }

    // -- extract_node_id_strings --

    #[test]
    fn node_id_strings_preserves_document_order() {
        let graph = serde_json::json!({
            "nodes": [
                {"id": "alpha"},
                {"id": "bravo"},
                {"id": "charlie"},
            ]
        });
        let out = extract_node_id_strings(&graph);
        assert_eq!(out, vec!["alpha", "bravo", "charlie"]);
    }

    #[test]
    fn node_id_strings_skips_missing_or_non_string_id() {
        let graph = serde_json::json!({
            "nodes": [
                {"id": "real"},
                {"id": 42},          // numeric — skipped
                {},                   // no id — skipped
                {"id": "another"},
            ]
        });
        let out = extract_node_id_strings(&graph);
        assert_eq!(out, vec!["real", "another"]);
    }

    #[test]
    fn node_id_strings_empty_when_no_nodes_field() {
        assert!(extract_node_id_strings(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn node_id_strings_collects_into_hashset_via_into_iter() {
        // The returned Vec is movable into a HashSet for callers that
        // want set semantics — covers the analytics.rs use case.
        let graph = serde_json::json!({
            "nodes": [{"id": "a"}, {"id": "b"}, {"id": "a"}]
        });
        let set: std::collections::HashSet<String> =
            extract_node_id_strings(&graph).into_iter().collect();
        assert_eq!(set.len(), 2);
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
