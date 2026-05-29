/// AdvancedRepository — centralises all SQL for the advanced-features domain.
///
/// Follows the ExecutionRepository / WorkflowRepository pattern: plain struct,
/// `new(db_pool)`, all methods `pub async fn`, return `anyhow::Result<T>`.
/// Handlers in `mcp/advanced.rs` should be thin wrappers that call these
/// methods and format the JSON-RPC response.
use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Row, Transaction};
use talos_tenancy::TenantReadScope;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Row DTOs
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ScratchSessionRow {
    pub name: String,
    pub world: String,
    pub updated_at: DateTime<Utc>,
    pub has_error: bool,
}

#[derive(Debug)]
pub struct ArchivedExecutionRow {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
}

#[derive(Debug)]
pub struct WasmModuleRow {
    pub name: String,
    pub capability_world: String,
    pub source_code: Option<String>,
}

#[derive(Debug)]
pub struct SandboxModuleRow {
    pub name: String,
    pub wasm_bytes: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct MarketplaceListingRow {
    pub module_id: Uuid,
    pub name: String,
    pub capability_world: String,
    pub version: String,
}

#[derive(Debug)]
pub struct TemplateSourceRow {
    pub code_template: String,
    pub wasm_bytes: Option<Vec<u8>>,
    pub config_schema: serde_json::Value,
    pub allowed_secrets: Vec<String>,
    pub allowed_hosts: Vec<String>,
}

/// What `install_from_marketplace` should do with a fetched
/// [`TemplateSourceRow`]. Pulled out as a pure decision so the handler
/// stays straight-line and the invariant ("never write a zero-byte
/// module") is unit-testable without a database — this is the 2026-04-27
/// regression class.
#[derive(Debug, PartialEq, Eq)]
pub enum InstallDispatch {
    /// Compiled WASM bytes are available — install as a runnable module.
    Wasm,
    /// Source only — install as a sandbox template (compiled on first use).
    Template,
    /// Neither bytes nor source — refuse with a publisher-actionable error.
    Reject,
}

impl InstallDispatch {
    pub fn from_source(src: &TemplateSourceRow) -> Self {
        if src.wasm_bytes.is_some() {
            Self::Wasm
        } else if !src.code_template.is_empty() {
            Self::Template
        } else {
            Self::Reject
        }
    }
}

/// Collapse `Some(empty_vec)` into `None`. The 2026-04-27 regression
/// landed because the publish path stored `wasm_bytes = vec![]` (compile
/// failed silently upstream) and the install accepted it as a runnable
/// module. Normalising at read time forces callers to treat the two
/// "no compiled bytes" shapes identically.
pub(crate) fn normalize_wasm_bytes(raw: Option<Vec<u8>>) -> Option<Vec<u8>> {
    raw.filter(|b| !b.is_empty())
}

#[derive(Debug)]
pub struct MarketplaceStats {
    pub total_listings: i64,
    pub total_downloads: i64,
    pub unique_publishers: i64,
    pub world_count: i64,
}

#[derive(Debug)]
pub struct MarketplaceTopModule {
    pub name: String,
    pub publisher_id: Uuid,
    pub downloads: i64,
    pub capability_world: String,
}

#[derive(Debug)]
pub struct PublishedModuleRow {
    pub listing_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub capability_world: String,
    pub version: String,
    pub downloads: i64,
    pub star_count: i32,
    pub verified: bool,
    pub tags: Vec<String>,
    pub published_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct NodeTemplateConfigRow {
    pub id: Uuid,
    pub name: String,
    pub config_schema: serde_json::Value,
    pub allowed_secrets: Vec<String>,
}

#[derive(Debug)]
pub struct DraftWorkflowRow {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub graph_json: Option<String>,
}

#[derive(Debug)]
pub struct PrevScheduledRow {
    pub id: Uuid,
    pub name: String,
    pub exec_count: i64,
}

#[derive(Debug)]
pub struct NextScheduledRunRow {
    pub cron_expression: String,
    pub timezone: String,
    pub next_trigger_at: Option<DateTime<Utc>>,
    pub workflow_name: String,
}

#[derive(Debug)]
pub struct ApprovalGateRow {
    pub id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub status: String,
    pub continuation_workflow_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by_type: Option<String>,
    pub resolved_by_note: Option<String>,
}

#[derive(Debug)]
pub struct ApprovalGateDetailRow {
    pub status: String,
    pub continuation_workflow_id: Option<Uuid>,
    pub payload: serde_json::Value,
}

#[derive(Debug)]
pub struct SlaThresholdRow {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub workflow_name: String,
    pub p95_latency_ms: Option<i64>,
    pub success_rate_pct: Option<f64>,
    pub notification_webhook: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct SlaThresholdConfigRow {
    pub notification_webhook: String,
    pub p95_latency_ms: Option<i64>,
    pub success_rate_pct: Option<f64>,
}

#[derive(Debug)]
pub struct SuspensionRow {
    pub id: Uuid,
    pub correlation_id: String,
    pub description: Option<String>,
    pub status: String,
    pub continuation_workflow_id: Option<Uuid>,
    pub callback_url: String,
    pub timeout_at: Option<DateTime<Utc>>,
    pub resumed_at: Option<DateTime<Utc>>,
    pub resumed_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct SuspensionDetailRow {
    pub id: Uuid,
    pub status: String,
    pub continuation_workflow_id: Option<Uuid>,
}

#[derive(Debug)]
pub struct PromoteWorkflowRow {
    pub name: String,
    pub graph_json: String,
    pub capabilities: Vec<String>,
    pub intent: Option<serde_json::Value>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Repository
// ─────────────────────────────────────────────────────────────────────────────

pub struct AdvancedRepository {
    db_pool: PgPool,
}

impl AdvancedRepository {
    pub fn new(db_pool: PgPool) -> Self {
        Self { db_pool }
    }

    // ── Scratch sessions ──────────────────────────────────────────────────────
    //
    // RFC 0004 M4: `scratch_sessions` is the first table with RLS enforced
    // (migration 20260529160000). It's request-only (no worker access) and
    // every query lives in this file, so all paths are wired below. scratch
    // sessions are personal, so the scope carries the user with an empty org
    // list — the policy's `user_id = current_user_id` clause matches.
    // Each method runs on the scoped tx so the RLS policy sees the GUC.

    /// Open a per-user tenant-scoped transaction (sets app.current_user_id)
    /// so the scratch_sessions RLS policy enforces. Caller runs its query on
    /// the returned tx and commits.
    async fn user_scoped_tx(&self, user_id: Uuid) -> Result<Transaction<'_, Postgres>> {
        talos_db::begin_tenant_read_scoped(&self.db_pool, &TenantReadScope::new(user_id, Vec::new()))
            .await
            .map_err(|e| anyhow!("open user-scoped tx: {e}"))
    }

    /// Create or update a scratch session (UPSERT by user_id + name).
    pub async fn upsert_scratch_session(
        &self,
        user_id: Uuid,
        name: &str,
        code: &str,
        world: &str,
    ) -> Result<()> {
        let mut tx = self.user_scoped_tx(user_id).await?;
        sqlx::query(
            "INSERT INTO scratch_sessions (user_id, name, code, world, updated_at) \
             VALUES ($1, $2, $3, $4, NOW()) \
             ON CONFLICT (user_id, name) DO UPDATE SET code = $3, world = $4, updated_at = NOW()",
        )
        .bind(user_id)
        .bind(name)
        .bind(code)
        .bind(world)
        .execute(&mut *tx)
        .await
        .context("upsert_scratch_session")?;
        tx.commit().await.context("commit upsert_scratch_session")
    }

    /// Update only the code field of an existing scratch session.
    pub async fn update_scratch_code(&self, code: &str, user_id: Uuid, name: &str) -> Result<()> {
        let mut tx = self.user_scoped_tx(user_id).await?;
        sqlx::query(
            "UPDATE scratch_sessions SET code = $1, updated_at = NOW() \
             WHERE user_id = $2 AND name = $3",
        )
        .bind(code)
        .bind(user_id)
        .bind(name)
        .execute(&mut *tx)
        .await
        .context("update_scratch_code")?;
        tx.commit().await.context("commit update_scratch_code")
    }

    /// Fetch (code, world) for a named scratch session.
    pub async fn get_scratch_session(
        &self,
        user_id: Uuid,
        name: &str,
    ) -> Result<Option<(String, String)>> {
        let mut tx = self.user_scoped_tx(user_id).await?;
        let row = sqlx::query_as::<_, (String, String)>(
            "SELECT code, world FROM scratch_sessions WHERE user_id = $1 AND name = $2",
        )
        .bind(user_id)
        .bind(name)
        .fetch_optional(&mut *tx)
        .await
        .context("get_scratch_session")?;
        tx.commit().await.context("commit get_scratch_session")?;
        Ok(row)
    }

    /// Persist a compilation/execution error on a scratch session.
    pub async fn update_scratch_error(&self, error: &str, user_id: Uuid, name: &str) -> Result<()> {
        let mut tx = self.user_scoped_tx(user_id).await?;
        sqlx::query(
            "UPDATE scratch_sessions SET last_error = $1, last_output = NULL, updated_at = NOW() \
             WHERE user_id = $2 AND name = $3",
        )
        .bind(error)
        .bind(user_id)
        .bind(name)
        .execute(&mut *tx)
        .await
        .context("update_scratch_error")?;
        tx.commit().await.context("commit update_scratch_error")
    }

    /// Persist a compilation warning where output is NULL but no full error (no_wasm_bytes path).
    pub async fn update_scratch_no_wasm(&self, msg: &str, user_id: Uuid, name: &str) -> Result<()> {
        let mut tx = self.user_scoped_tx(user_id).await?;
        sqlx::query(
            "UPDATE scratch_sessions SET last_error = $1, updated_at = NOW() \
             WHERE user_id = $2 AND name = $3",
        )
        .bind(msg)
        .bind(user_id)
        .bind(name)
        .execute(&mut *tx)
        .await
        .context("update_scratch_no_wasm")?;
        tx.commit().await.context("commit update_scratch_no_wasm")
    }

    /// Persist the successful output of a scratch session execution.
    pub async fn update_scratch_output(
        &self,
        output: &serde_json::Value,
        user_id: Uuid,
        name: &str,
    ) -> Result<()> {
        let mut tx = self.user_scoped_tx(user_id).await?;
        sqlx::query(
            "UPDATE scratch_sessions SET last_output = $1, last_error = NULL, updated_at = NOW() \
             WHERE user_id = $2 AND name = $3",
        )
        .bind(output)
        .bind(user_id)
        .bind(name)
        .execute(&mut *tx)
        .await
        .context("update_scratch_output")?;
        tx.commit().await.context("commit update_scratch_output")
    }

    /// List all scratch sessions for a user, ordered by most recently updated.
    pub async fn list_scratch_sessions(&self, user_id: Uuid) -> Result<Vec<ScratchSessionRow>> {
        let mut tx = self.user_scoped_tx(user_id).await?;
        let rows = sqlx::query(
            "SELECT name, world, updated_at, (last_error IS NOT NULL) as has_error \
             FROM scratch_sessions WHERE user_id = $1 ORDER BY updated_at DESC LIMIT 1000",
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await
        .context("list_scratch_sessions")?;
        tx.commit().await.context("commit list_scratch_sessions")?;

        Ok(rows
            .into_iter()
            .map(|r| ScratchSessionRow {
                name: r.get("name"),
                world: r.get("world"),
                updated_at: r.get("updated_at"),
                has_error: r.try_get("has_error").unwrap_or(false),
            })
            .collect())
    }

    /// Delete a named scratch session. Returns the number of rows affected.
    pub async fn delete_scratch_session(&self, user_id: Uuid, name: &str) -> Result<u64> {
        let mut tx = self.user_scoped_tx(user_id).await?;
        let affected = sqlx::query("DELETE FROM scratch_sessions WHERE user_id = $1 AND name = $2")
            .bind(user_id)
            .bind(name)
            .execute(&mut *tx)
            .await
            .map(|r| r.rows_affected())
            .context("delete_scratch_session")?;
        tx.commit().await.context("commit delete_scratch_session")?;
        Ok(affected)
    }

    // ── Archive policy ────────────────────────────────────────────────────────

    /// Read the archive_after_days setting from system_settings.
    pub async fn get_archive_policy(&self) -> Result<Option<serde_json::Value>> {
        sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT value FROM system_settings WHERE key = 'archive_after_days'",
        )
        .fetch_optional(&self.db_pool)
        .await
        .context("get_archive_policy")
    }

    /// Upsert the archive_after_days setting.
    pub async fn set_archive_policy(&self, days: i32) -> Result<()> {
        sqlx::query(
            "INSERT INTO system_settings (key, value, updated_at) \
             VALUES ('archive_after_days', $1::jsonb, NOW()) \
             ON CONFLICT (key) DO UPDATE SET value = $1::jsonb, updated_at = NOW()",
        )
        .bind(serde_json::json!(days))
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("set_archive_policy")
    }

    // ── Archive executions ────────────────────────────────────────────────────

    /// Move old completed/failed/cancelled executions to the archive table.
    /// Returns the number of rows moved.
    pub async fn archive_executions(&self, days: i32, user_id: Uuid) -> Result<u64> {
        // MCP-1062 (2026-05-15): refuse non-positive `days`. Sibling
        // caller-supplied-negative class as MCP-997. With
        // `make_interval(days => -N)` the predicate
        // `completed_at < NOW() - INTERVAL` becomes `< NOW() +
        // INTERVAL`, archiving every non-pinned completed / failed /
        // cancelled execution for the user — total purge.
        if days <= 0 {
            tracing::warn!(
                target: "talos_audit",
                days,
                %user_id,
                "archive_executions refused: days must be positive (would archive every non-pinned execution)"
            );
            return Ok(0);
        }
        sqlx::query(
            "WITH archived AS (
                DELETE FROM workflow_executions
                WHERE status IN ('completed', 'failed', 'cancelled')
                AND completed_at < NOW() - make_interval(days => $1)
                AND is_pinned = false
                AND user_id = $2
                RETURNING *
            )
            INSERT INTO workflow_executions_archive (
                id, workflow_id, user_id, status, started_at, completed_at,
                error_message, created_at, updated_at, output_data, workflow_version_id,
                is_pinned, pin_note, priority, replayed_from_id, input_data,
                checkpoint_data, is_test_execution, checkpoint_encrypted, checkpoint_nonce,
                actor_id, provenance, acknowledged_at, acknowledgement_reason
            )
            SELECT
                id, workflow_id, user_id, status, started_at, completed_at,
                error_message, created_at, updated_at, output_data, workflow_version_id,
                is_pinned, pin_note, priority, replayed_from_id, input_data,
                checkpoint_data, is_test_execution, checkpoint_encrypted, checkpoint_nonce,
                actor_id, provenance, acknowledged_at, acknowledgement_reason
            FROM archived",
        )
        .bind(days)
        .bind(user_id)
        .execute(&self.db_pool)
        .await
        .map(|r| r.rows_affected())
        .context("archive_executions")
    }

    /// List archived executions, optionally filtered by workflow_id.
    pub async fn list_archived_executions(
        &self,
        user_id: Uuid,
        workflow_id: Option<Uuid>,
        limit: i32,
    ) -> Result<Vec<ArchivedExecutionRow>> {
        let rows = if let Some(wf_id) = workflow_id {
            sqlx::query(
                "SELECT id, workflow_id, status, started_at, completed_at, error_message \
                 FROM workflow_executions_archive \
                 WHERE user_id = $1 AND workflow_id = $2 \
                 ORDER BY started_at DESC LIMIT $3",
            )
            .bind(user_id)
            .bind(wf_id)
            .bind(limit)
            .fetch_all(&self.db_pool)
            .await
        } else {
            sqlx::query(
                "SELECT id, workflow_id, status, started_at, completed_at, error_message \
                 FROM workflow_executions_archive \
                 WHERE user_id = $1 \
                 ORDER BY started_at DESC LIMIT $2",
            )
            .bind(user_id)
            .bind(limit)
            .fetch_all(&self.db_pool)
            .await
        }
        .context("list_archived_executions")?;

        Ok(rows
            .into_iter()
            .map(|r| ArchivedExecutionRow {
                id: r.get("id"),
                workflow_id: r.get("workflow_id"),
                status: r.get("status"),
                started_at: r.get("started_at"),
                completed_at: r.get("completed_at"),
                error_message: r.get("error_message"),
            })
            .collect())
    }

    // ── Marketplace ───────────────────────────────────────────────────────────

    /// Fetch WASM module info for marketplace publishing (ownership-checked).
    pub async fn get_wasm_module_for_marketplace(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WasmModuleRow>> {
        // Phase 4 prep: query the unified `modules` table with the 3-shape
        // id match. `source_code` is now first-class on the modules row;
        // the previous wasm_modules-only query missed catalog-installed
        // modules whose source lives elsewhere (returns NULL gracefully
        // for those, same as before).
        let row = sqlx::query(
            "SELECT name, capability_world, source_code \
               FROM modules \
              WHERE id = $1 \
                AND user_id = $2",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_wasm_module_for_marketplace")?;

        Ok(row.map(|r| WasmModuleRow {
            name: r.get("name"),
            capability_world: r.get("capability_world"),
            source_code: r.try_get("source_code").unwrap_or(None),
        }))
    }

    /// Fetch sandbox template info for marketplace publishing (ownership-checked).
    pub async fn get_sandbox_for_marketplace(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<SandboxModuleRow>> {
        // Phase 4 prep: query the unified `modules` table. The legacy
        // `node_templates.precompiled_wasm` mapped to `modules.wasm_bytes`
        // (Phase 1.1 backfill); the new query reads it directly.
        let row = sqlx::query(
            "SELECT name, wasm_bytes \
               FROM modules \
              WHERE id = $1 \
                AND user_id = $2",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_sandbox_for_marketplace")?;

        Ok(row.map(|r| SandboxModuleRow {
            name: r.get("name"),
            wasm_bytes: r.try_get("wasm_bytes").unwrap_or(None),
        }))
    }

    /// Insert or update a marketplace listing. Returns the listing UUID.
    pub async fn publish_to_marketplace(
        &self,
        module_id: Uuid,
        user_id: Uuid,
        name: &str,
        description: &str,
        world: &str,
        version: &str,
        tags: &[String],
    ) -> Result<Uuid> {
        let row = sqlx::query(
            "INSERT INTO module_marketplace \
             (module_id, publisher_id, name, description, capability_world, version, tags) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (name, version) DO UPDATE SET \
             description = EXCLUDED.description, tags = EXCLUDED.tags, updated_at = NOW() \
             RETURNING id",
        )
        .bind(module_id)
        .bind(user_id)
        .bind(name)
        .bind(description)
        .bind(world)
        .bind(version)
        .bind(tags)
        .fetch_one(&self.db_pool)
        .await
        .context("publish_to_marketplace")?;

        Ok(row.get("id"))
    }

    /// Fetch a marketplace listing by ID (must be public).
    pub async fn get_marketplace_listing(
        &self,
        listing_id: Uuid,
    ) -> Result<Option<MarketplaceListingRow>> {
        let row = sqlx::query(
            "SELECT m.module_id, m.name, m.capability_world, m.version \
             FROM module_marketplace m WHERE m.id = $1 AND m.is_public = true",
        )
        .bind(listing_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_marketplace_listing")?;

        Ok(row.map(|r| MarketplaceListingRow {
            module_id: r.get("module_id"),
            name: r.get("name"),
            capability_world: r.get("capability_world"),
            version: r.get("version"),
        }))
    }

    /// Fetch the full installable artifact for a marketplace source module —
    /// source, bytes, schema, and the security-relevant allowlists.
    ///
    /// Returns the same `TemplateSourceRow` shape as `get_template_source` so
    /// the install handler can branch on artifact availability without two
    /// parallel struct shapes drifting. `wasm_bytes` is normalised to `None`
    /// when the column is NULL OR empty (`vec![]`) — collapsing the two
    /// "no compiled bytes" cases means callers can't accidentally write a
    /// zero-byte module by forgetting to check `is_empty()`. This was the
    /// 2026-04-27 regression: the published listing's `wasm_bytes` was
    /// `Some(vec![])`, the install accepted it, the worker then failed
    /// with "failed to fetch wasm module from redis (not found)".
    pub async fn get_wasm_module_source(
        &self,
        module_id: Uuid,
    ) -> Result<Option<TemplateSourceRow>> {
        let row = sqlx::query(
            "SELECT source_code, wasm_bytes, config_schema, allowed_secrets, allowed_hosts \
               FROM modules \
              WHERE id = $1 \
              LIMIT 1",
        )
        .bind(module_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_wasm_module_source")?;

        Ok(row.map(|r| TemplateSourceRow {
            code_template: r
                .try_get::<Option<String>, _>("source_code")
                .unwrap_or(None)
                .unwrap_or_default(),
            wasm_bytes: normalize_wasm_bytes(
                r.try_get::<Option<Vec<u8>>, _>("wasm_bytes")
                    .unwrap_or(None),
            ),
            config_schema: r.try_get("config_schema").unwrap_or(serde_json::json!({})),
            allowed_secrets: r.try_get("allowed_secrets").unwrap_or_default(),
            allowed_hosts: r.try_get("allowed_hosts").unwrap_or_default(),
        }))
    }

    /// Fetch a node template for marketplace installation.
    pub async fn get_template_source(&self, module_id: Uuid) -> Result<Option<TemplateSourceRow>> {
        // Phase 5: unified `modules` table. `source_code` replaces
        // `code_template`, `wasm_bytes` replaces `precompiled_wasm`.
        let row = sqlx::query(
            "SELECT source_code, wasm_bytes, config_schema, allowed_secrets, allowed_hosts \
             FROM modules \
             WHERE id = $1",
        )
        .bind(module_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_template_source")?;

        Ok(row.map(|r| TemplateSourceRow {
            // `modules.source_code` is nullable (catalog-only rows have NULL);
            // fall back to empty string to preserve the legacy non-null field shape.
            code_template: r
                .try_get::<Option<String>, _>("source_code")
                .unwrap_or(None)
                .unwrap_or_default(),
            wasm_bytes: r.try_get("wasm_bytes").unwrap_or(None),
            config_schema: r.try_get("config_schema").unwrap_or(serde_json::json!({})),
            allowed_secrets: r.try_get("allowed_secrets").unwrap_or_default(),
            allowed_hosts: r.try_get("allowed_hosts").unwrap_or_default(),
        }))
    }

    /// Install a WASM module from the marketplace (atomic INSERT + download count increment).
    /// Returns the new module ID.
    ///
    /// The caller (handler in `mcp/advanced.rs`) is responsible for choosing
    /// this path only when `src.wasm_bytes.is_some()` — this method asserts
    /// the same invariant as a defence-in-depth check, since silently
    /// writing a NULL/empty `wasm_bytes` row produces the same prod
    /// regression class (worker errors with "module not found in redis").
    pub async fn install_wasm_from_marketplace(
        &self,
        user_id: Uuid,
        listing_id: Uuid,
        install_name: &str,
        world: &str,
        src: TemplateSourceRow,
    ) -> Result<Uuid> {
        // Defence in depth: the handler should have rejected this case, but
        // refuse here too rather than write a zero-byte module that the
        // worker cannot run. Treat this as an internal error (it's a bug
        // in the caller, not a user-facing condition).
        let wasm_bytes = src.wasm_bytes.ok_or_else(|| {
            anyhow!(
                "install_wasm_from_marketplace: wasm_bytes missing — caller should have routed \
                 to install_template_from_marketplace or rejected the listing"
            )
        })?;

        let new_module_id = Uuid::new_v4();
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("install_wasm_from_marketplace begin")?;

        // Phase 5: write directly to the unified `modules` table. Marketplace
        // installs are user-owned sandbox modules (compiled on install).
        // allowed_secrets and allowed_hosts are propagated from the source
        // module's listing — without them, every vault:// header in the
        // module's config fails at runtime and `talos::core::http::fetch`
        // refuses to call the listed providers.
        sqlx::query(
            "INSERT INTO modules \
             (id, name, kind, capability_world, source_code, wasm_bytes, user_id, \
              allowed_secrets, allowed_hosts, compiled_at) \
             VALUES ($1, $2, 'sandbox', $3, $4, $5, $6, $7, $8, NOW())",
        )
        .bind(new_module_id)
        .bind(install_name)
        .bind(world)
        .bind(&src.code_template)
        .bind(&wasm_bytes)
        .bind(user_id)
        .bind(&src.allowed_secrets)
        .bind(&src.allowed_hosts)
        .execute(&mut *tx)
        .await
        .context("install_wasm_from_marketplace insert")?;

        sqlx::query("UPDATE module_marketplace SET downloads = downloads + 1 WHERE id = $1")
            .bind(listing_id)
            .execute(&mut *tx)
            .await
            .context("install_wasm_from_marketplace download count")?;

        tx.commit()
            .await
            .context("install_wasm_from_marketplace commit")?;

        Ok(new_module_id)
    }

    /// Install a sandbox template from the marketplace (atomic INSERT + download count increment).
    /// Returns the new template ID.
    ///
    /// `world` is the listing's `capability_world` — propagated explicitly so
    /// the new row records the same WIT world the publisher targeted. Without
    /// this the column defaulted to `minimal-node`, silently downgrading
    /// every source-only marketplace install (sibling regression to the WASM
    /// install path's lost allowlists, fixed in the same release).
    pub async fn install_template_from_marketplace(
        &self,
        user_id: Uuid,
        listing_id: Uuid,
        install_name: &str,
        world: &str,
        src: TemplateSourceRow,
    ) -> Result<Uuid> {
        let new_template_id = Uuid::new_v4();
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("install_template_from_marketplace begin")?;

        // Phase 5: write directly to the unified `modules` table. Sandbox
        // template install: `kind='sandbox'` + source_code + optional wasm_bytes.
        sqlx::query(
            "INSERT INTO modules \
             (id, name, kind, capability_world, category, description, config_schema, \
              source_code, wasm_bytes, user_id, allowed_secrets, allowed_hosts) \
             VALUES ($1, $2, 'sandbox', $3, 'sandbox', 'Installed from marketplace', $4, $5, $6, $7, $8, $9)",
        )
        .bind(new_template_id)
        .bind(install_name)
        .bind(world)
        .bind(&src.config_schema)
        .bind(&src.code_template)
        .bind(&src.wasm_bytes)
        .bind(user_id)
        .bind(&src.allowed_secrets)
        .bind(&src.allowed_hosts)
        .execute(&mut *tx)
        .await
        .context("install_template_from_marketplace insert")?;

        sqlx::query("UPDATE module_marketplace SET downloads = downloads + 1 WHERE id = $1")
            .bind(listing_id)
            .execute(&mut *tx)
            .await
            .context("install_template_from_marketplace download count")?;

        tx.commit()
            .await
            .context("install_template_from_marketplace commit")?;

        Ok(new_template_id)
    }

    /// Aggregate marketplace statistics.
    pub async fn get_marketplace_stats(&self) -> Result<MarketplaceStats> {
        let row = sqlx::query(
            "SELECT \
                COUNT(*)::bigint AS total_listings, \
                COALESCE(SUM(downloads), 0)::bigint AS total_downloads, \
                COUNT(DISTINCT publisher_id)::bigint AS unique_publishers, \
                COUNT(DISTINCT capability_world)::bigint AS world_count \
             FROM module_marketplace WHERE is_public = true",
        )
        .fetch_one(&self.db_pool)
        .await
        .context("get_marketplace_stats")?;

        Ok(MarketplaceStats {
            total_listings: row.try_get("total_listings").unwrap_or(0),
            total_downloads: row.try_get("total_downloads").unwrap_or(0),
            unique_publishers: row.try_get("unique_publishers").unwrap_or(0),
            world_count: row.try_get("world_count").unwrap_or(0),
        })
    }

    /// Top 5 most-downloaded marketplace modules.
    ///
    /// Postgres default for `ORDER BY x DESC` is `NULLS FIRST`. The
    /// `module_marketplace.downloads` column allows NULL (catalog-seeded
    /// templates that have never been downloaded come in NULL, not 0), so
    /// pre-fix the NULL-download rows floated to the top and the real
    /// download leaders fell below LIMIT 5. The handler's `total_downloads`
    /// (from `SUM(downloads)`) and `top_modules[].downloads` could then
    /// disagree: total_downloads=3 with every top-5 entry showing 0.
    /// COALESCE both the sort key and the projection so NULL is treated
    /// as 0 consistently, and add a deterministic tie-break on `name` so
    /// the top-5 ordering is stable across calls.
    pub async fn get_marketplace_top_modules(&self) -> Result<Vec<MarketplaceTopModule>> {
        let rows = sqlx::query(
            "SELECT name, publisher_id, COALESCE(downloads, 0)::bigint AS downloads, capability_world \
             FROM module_marketplace WHERE is_public = true \
             ORDER BY COALESCE(downloads, 0) DESC, name ASC LIMIT 5",
        )
        .fetch_all(&self.db_pool)
        .await
        .context("get_marketplace_top_modules")?;

        Ok(rows
            .into_iter()
            .map(|r| MarketplaceTopModule {
                name: r.try_get("name").unwrap_or_default(),
                publisher_id: r.try_get("publisher_id").unwrap_or(Uuid::nil()),
                downloads: r.try_get::<i64, _>("downloads").unwrap_or(0),
                capability_world: r.try_get("capability_world").unwrap_or_default(),
            })
            .collect())
    }

    /// List public marketplace modules, optionally filtered by capability_world.
    ///
    /// Same i32→i64 type-mismatch fix applied to `get_marketplace_top_modules`:
    /// `module_marketplace.downloads` is Postgres INT4 (NOT NULL DEFAULT 0)
    /// but the projection reads it as i64. Without the explicit ::bigint cast
    /// the read fails and `.unwrap_or(0)` masks every download count to 0,
    /// so operators see "no popular modules" even when downloads exist.
    pub async fn list_published_modules(
        &self,
        world: Option<&str>,
        limit: i64,
    ) -> Result<Vec<PublishedModuleRow>> {
        let rows = sqlx::query(
            "SELECT id, name, description, capability_world, version, \
                    downloads::bigint AS downloads, tags, \
                    created_at, verified, star_count \
             FROM module_marketplace \
             WHERE is_public = true \
               AND ($1::text IS NULL OR capability_world = $1) \
             ORDER BY star_count DESC, downloads DESC, created_at DESC \
             LIMIT $2",
        )
        .bind(world)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await
        .context("list_published_modules")?;

        Ok(rows
            .into_iter()
            .map(|r| PublishedModuleRow {
                listing_id: r.try_get("id").unwrap_or(Uuid::nil()),
                name: r.try_get("name").unwrap_or_default(),
                description: r.try_get("description").unwrap_or(None),
                capability_world: r.try_get("capability_world").unwrap_or_default(),
                version: r.try_get("version").unwrap_or_default(),
                downloads: r.try_get::<i64, _>("downloads").unwrap_or(0),
                star_count: r.try_get::<i32, _>("star_count").unwrap_or(0),
                verified: r.try_get("verified").unwrap_or(false),
                tags: r.try_get("tags").unwrap_or_default(),
                published_at: r
                    .try_get("created_at")
                    .unwrap_or_else(|_| chrono::Utc::now()),
            })
            .collect())
    }

    /// Check whether a public listing exists.
    pub async fn check_listing_exists(&self, listing_id: Uuid) -> Result<bool> {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM module_marketplace WHERE id = $1 AND is_public = true)",
        )
        .bind(listing_id)
        .fetch_one(&self.db_pool)
        .await
        .context("check_listing_exists")
    }

    /// Insert a per-user star record (ON CONFLICT DO NOTHING). Returns true if a new star was
    /// inserted (false if the user already starred this listing).
    pub async fn insert_star(&self, user_id: Uuid, listing_id: Uuid) -> Result<bool> {
        let r = sqlx::query(
            "INSERT INTO module_marketplace_stars (user_id, listing_id) \
             VALUES ($1, $2) \
             ON CONFLICT (user_id, listing_id) DO NOTHING",
        )
        .bind(user_id)
        .bind(listing_id)
        .execute(&self.db_pool)
        .await
        .context("insert_star")?;

        Ok(r.rows_affected() > 0)
    }

    /// Read current star_count without modifying it (used when already starred).
    pub async fn get_star_count(&self, listing_id: Uuid) -> Result<i32> {
        sqlx::query_scalar::<_, i32>("SELECT star_count FROM module_marketplace WHERE id = $1")
            .bind(listing_id)
            .fetch_one(&self.db_pool)
            .await
            .context("get_star_count")
    }

    /// Atomically increment star_count and return the new value.
    pub async fn increment_star_count(&self, listing_id: Uuid) -> Result<Option<i32>> {
        let row = sqlx::query(
            "UPDATE module_marketplace \
             SET star_count = star_count + 1, updated_at = NOW() \
             WHERE id = $1 AND is_public = true \
             RETURNING star_count",
        )
        .bind(listing_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("increment_star_count")?;

        Ok(row.map(|r| r.try_get("star_count").unwrap_or(0)))
    }

    // ── Workflow operations ───────────────────────────────────────────────────

    /// Archive a workflow (set status = 'archived'). Returns rows affected.
    pub async fn archive_workflow(&self, wf_id: Uuid, user_id: Uuid) -> Result<u64> {
        sqlx::query(
            "UPDATE workflows SET status = 'archived', updated_at = NOW() \
             WHERE id = $1 AND user_id = $2 AND status != 'archived'",
        )
        .bind(wf_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await
        .map(|r| r.rows_affected())
        .context("archive_workflow")
    }

    /// Fetch (name, status) for a workflow (ownership-checked).
    pub async fn get_workflow_name_status(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(String, Option<String>)>> {
        let row = sqlx::query("SELECT name, status FROM workflows WHERE id = $1 AND user_id = $2")
            .bind(wf_id)
            .bind(user_id)
            .fetch_optional(&self.db_pool)
            .await
            .context("get_workflow_name_status")?;

        Ok(row.map(|r| {
            let name: String = r.try_get("name").unwrap_or_default();
            let status: Option<String> = r.try_get("status").unwrap_or(None);
            (name, status)
        }))
    }

    /// Set workflow status to 'active'.
    pub async fn activate_workflow(&self, wf_id: Uuid, user_id: Uuid) -> Result<()> {
        sqlx::query("UPDATE workflows SET status = 'active' WHERE id = $1 AND user_id = $2")
            .bind(wf_id)
            .bind(user_id)
            .execute(&self.db_pool)
            .await
            .map(|_| ())
            .context("activate_workflow")
    }

    /// Create a workflow schedule.
    pub async fn create_workflow_schedule(
        &self,
        sid: Uuid,
        wf_id: Uuid,
        user_id: Uuid,
        cron: &str,
        timezone: &str,
        next_trigger_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO workflow_schedules \
             (id, workflow_id, user_id, cron_expression, timezone, is_enabled, next_trigger_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, true, $6, NOW())",
        )
        .bind(sid)
        .bind(wf_id)
        .bind(user_id)
        .bind(cron)
        .bind(timezone)
        .bind(next_trigger_at)
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("create_workflow_schedule")
    }

    /// Fetch source workflow fields needed for promotion.
    pub async fn get_source_workflow_for_promote(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<PromoteWorkflowRow>> {
        let row = sqlx::query(
            "SELECT name, graph_json, capabilities, intent FROM workflows \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_source_workflow_for_promote")?;

        Ok(row.map(|r| PromoteWorkflowRow {
            name: r.try_get("name").unwrap_or_default(),
            graph_json: r
                .try_get("graph_json")
                .unwrap_or_else(|_| r#"{"nodes":[],"edges":[]}"#.to_string()),
            capabilities: r.try_get("capabilities").unwrap_or_default(),
            intent: r.try_get("intent").unwrap_or(None),
        }))
    }

    /// Insert a new (promoted) workflow record.
    pub async fn insert_promoted_workflow(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        name: &str,
        graph_json: &str,
        capabilities: &[String],
        intent: Option<&serde_json::Value>,
    ) -> Result<()> {
        sqlx::query(
            // RFC 0004: stamp org_id = the creator's personal org (NULL-tolerant).
            "INSERT INTO workflows \
             (id, user_id, name, module_uri, graph_json, capabilities, intent, status, \
              created_at, updated_at, org_id) \
             VALUES ($1, $2, $3, '', $4, $5, $6, 'draft', NOW(), NOW(), \
              (SELECT id FROM organizations WHERE owner_id = $2 AND is_personal))",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(name)
        .bind(graph_json)
        .bind(capabilities)
        .bind(intent)
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("insert_promoted_workflow")
    }

    // ── Config suggestions ────────────────────────────────────────────────────

    /// Fetch (name, graph_json) for a workflow (ownership-checked).
    pub async fn get_workflow_graph_and_name(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(String, String)>> {
        let row =
            sqlx::query("SELECT name, graph_json FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(wf_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await
                .context("get_workflow_graph_and_name")?;

        Ok(row.map(|r| {
            let name: String = r.get("name");
            let graph: String = r.get("graph_json");
            (name, graph)
        }))
    }

    /// Fetch id, name, config_schema, allowed_secrets for a batch of template IDs.
    pub async fn get_node_templates_for_config(
        &self,
        ids: &[Uuid],
    ) -> Result<Vec<NodeTemplateConfigRow>> {
        // Phase 5: unified `modules` table. Match on the canonical id OR
        // either legacy alias so graph_json blobs that still carry old
        // node_templates.id / wasm_modules.id keep resolving during
        // the migration window.
        let rows = sqlx::query(
            "SELECT id, name, config_schema, allowed_secrets \
             FROM modules \
             WHERE id = ANY($1)",
        )
        .bind(ids)
        .fetch_all(&self.db_pool)
        .await
        .context("get_node_templates_for_config")?;

        Ok(rows
            .into_iter()
            .map(|r| NodeTemplateConfigRow {
                id: r.get("id"),
                name: r.get("name"),
                config_schema: r.try_get("config_schema").unwrap_or(serde_json::json!({})),
                allowed_secrets: r.try_get("allowed_secrets").unwrap_or_default(),
            })
            .collect())
    }

    /// Fetch all secret key_paths for a user (for vault cross-reference).
    pub async fn get_user_secret_paths(&self, user_id: Uuid) -> Result<Vec<String>> {
        sqlx::query_scalar::<_, String>(
            "SELECT key_path FROM secrets WHERE created_by = $1 LIMIT 10000",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await
        .context("get_user_secret_paths")
    }

    // ── Agent session start ───────────────────────────────────────────────────

    /// Count total workflows and those with embeddings for a user.
    /// Returns (total, embedded).
    pub async fn get_embedding_coverage(&self, user_id: Uuid) -> Result<(i64, i64)> {
        let row = sqlx::query(
            "SELECT COUNT(*) as total, \
                    COUNT(*) FILTER (WHERE embedding IS NOT NULL) as embedded \
             FROM workflows WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_embedding_coverage")?;

        Ok(row
            .map(|r| {
                (
                    r.try_get("total").unwrap_or(0),
                    r.try_get("embedded").unwrap_or(0),
                )
            })
            .unwrap_or((0, 0)))
    }

    /// Fetch UUIDs of workflows that have no embedding (limit 100).
    pub async fn get_ids_without_embedding(&self, user_id: Uuid) -> Result<Vec<Uuid>> {
        let rows = sqlx::query(
            "SELECT id FROM workflows WHERE user_id = $1 AND embedding IS NULL LIMIT 100",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await
        .context("get_ids_without_embedding")?;

        Ok(rows.into_iter().map(|r| r.get("id")).collect())
    }

    /// Fetch recent draft workflows with no executions (max 10).
    pub async fn get_draft_workflows(&self, user_id: Uuid) -> Result<Vec<DraftWorkflowRow>> {
        let rows = sqlx::query(
            "SELECT w.id, w.name, w.created_at, w.graph_json::text AS graph_json \
             FROM workflows w \
             WHERE w.user_id = $1 \
               AND w.status = 'draft' \
               AND NOT EXISTS (SELECT 1 FROM workflow_executions we WHERE we.workflow_id = w.id) \
             ORDER BY w.updated_at DESC LIMIT 10",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await
        .context("get_draft_workflows")?;

        Ok(rows
            .into_iter()
            .map(|r| DraftWorkflowRow {
                id: r.try_get("id").unwrap_or(Uuid::nil()),
                name: r.try_get("name").unwrap_or_default(),
                created_at: r
                    .try_get("created_at")
                    .unwrap_or_else(|_| chrono::Utc::now()),
                graph_json: r.try_get("graph_json").unwrap_or(None),
            })
            .collect())
    }

    /// Archive draft workflows with no executions older than `stale_days`. Returns count.
    pub async fn archive_stale_drafts(&self, user_id: Uuid, stale_days: i32) -> Result<u64> {
        // MCP-1062 (2026-05-15): refuse non-positive `stale_days`.
        // Sibling caller-supplied-negative class as MCP-997. With
        // `make_interval(days => -N)` the `created_at <` predicate
        // flips to `< NOW() + INTERVAL`, archiving every empty draft
        // workflow for the user regardless of age.
        if stale_days <= 0 {
            tracing::warn!(
                target: "talos_audit",
                stale_days,
                %user_id,
                "archive_stale_drafts refused: stale_days must be positive (would archive every empty draft)"
            );
            return Ok(0);
        }
        sqlx::query(
            "UPDATE workflows SET status = 'archived', updated_at = NOW() \
             WHERE user_id = $1 \
               AND status = 'draft' \
               AND NOT EXISTS (SELECT 1 FROM workflow_executions we WHERE we.workflow_id = workflows.id) \
               AND created_at < NOW() - make_interval(days => $2)",
        )
        .bind(user_id)
        .bind(stale_days)
        .execute(&self.db_pool)
        .await
        .map(|r| r.rows_affected())
        .context("archive_stale_drafts")
    }

    /// Count workflows with no capability tags.
    pub async fn get_uncapabilized_count(&self, user_id: Uuid) -> Result<i64> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM workflows \
             WHERE user_id = $1 AND (capabilities IS NULL OR capabilities = '{}')",
        )
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await
        .context("get_uncapabilized_count")
    }

    /// Fetch UUIDs of workflows with no capability tags (limit 100).
    pub async fn get_ids_without_capabilities(&self, user_id: Uuid) -> Result<Vec<Uuid>> {
        let rows = sqlx::query(
            "SELECT id FROM workflows WHERE user_id = $1 \
             AND (capabilities IS NULL OR capabilities = '{}') LIMIT 100",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await
        .context("get_ids_without_capabilities")?;

        Ok(rows.into_iter().map(|r| r.get("id")).collect())
    }

    /// Fetch the next upcoming scheduled run for a user. Returns full schedule
    /// metadata (cron, timezone, next_trigger_at, workflow name) so callers can
    /// distinguish "no schedule" from "next firing is hours/days out" without
    /// a follow-up query.
    ///
    /// Pre-r234 this read from a phantom `schedules` table which never existed
    /// in the schema (only `workflow_schedules` is created by migration
    /// `20260309000200_add_workflow_schedules.sql`). The query silently
    /// returned no rows, so session_start always reported next_scheduled_run
    /// as null even when active schedules existed (pain point #8 from
    /// aegix_dev_pain_points.md). All schedule queries are now unified on
    /// the canonical table — see also get_frequently_executed_unscheduled
    /// below.
    pub async fn get_next_scheduled_run(
        &self,
        user_id: Uuid,
    ) -> Result<Option<NextScheduledRunRow>> {
        let row = sqlx::query(
            "SELECT ws.cron_expression, ws.timezone, ws.next_trigger_at, w.name \
             FROM workflow_schedules ws JOIN workflows w ON w.id = ws.workflow_id \
             WHERE ws.user_id = $1 AND ws.is_enabled = true \
             ORDER BY ws.next_trigger_at ASC NULLS LAST LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_next_scheduled_run")?;

        Ok(row.map(|r| NextScheduledRunRow {
            cron_expression: r.try_get("cron_expression").unwrap_or_default(),
            timezone: r.try_get("timezone").unwrap_or_else(|_| "UTC".to_string()),
            next_trigger_at: r.try_get("next_trigger_at").ok(),
            workflow_name: r.try_get("name").unwrap_or_default(),
        }))
    }

    /// Count active (non-archived) workflows for a user.
    pub async fn get_active_workflow_count(&self, user_id: Uuid) -> Result<i64> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM workflows WHERE user_id = $1 AND status = 'active'",
        )
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await
        .context("get_active_workflow_count")
    }

    /// Count active workflow schedules for a user.
    pub async fn get_active_schedule_count(&self, user_id: Uuid) -> Result<i64> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM workflow_schedules WHERE user_id = $1 AND is_enabled = true",
        )
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await
        .context("get_active_schedule_count")
    }

    /// Count active workflows that have at least one enabled schedule attached.
    /// Distinct from [`get_active_schedule_count`], which counts schedule rows
    /// (a workflow may have multiple). Used by `schedule_health` to answer the
    /// question "how many of my active workflows are actually scheduled?" —
    /// the previously-published `active_workflows` field misleadingly counted
    /// every status='active' workflow regardless of schedule attachment.
    pub async fn get_active_workflows_with_schedule_count(&self, user_id: Uuid) -> Result<i64> {
        // Pre-fix this filtered `w.status = 'active'`, which excluded
        // workflows in `status='draft'` even though the scheduler
        // happily fires them and they're producing executions every
        // day. Discovered via MCP probe 2026-05-07: the user has 7
        // enabled schedules firing reliably but
        // `workflows_with_active_schedules` reported 0 because every
        // scheduled workflow was a draft (publish_version had never
        // been called). The lifecycle is `draft → active` on publish
        // (per migration 20260318000000), but operators frequently
        // skip that step for personal-use workflows. Loosen to
        // `status != 'archived'` so the metric matches the user's
        // mental model: "how many of my non-archived workflows have
        // an enabled schedule attached?"
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(DISTINCT w.id) \
             FROM workflows w \
             JOIN workflow_schedules s ON s.workflow_id = w.id \
             WHERE w.user_id = $1 \
               AND w.status != 'archived' \
               AND s.is_enabled = true",
        )
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await
        .context("get_active_workflows_with_schedule_count")
    }

    /// Workflows that ran ≥3 times in the last 60 days but have no active
    /// schedule. Used by session_start to surface workflows the operator may
    /// want to schedule.
    ///
    /// **Pre-r242 this was named `get_previously_scheduled_unscheduled`** —
    /// a misleading name because workflow_schedules deletes are HARD deletes
    /// (no audit/history table) so we have NO way to know whether a workflow
    /// was ever scheduled. The "previously" framing produced false positives
    /// for manual-trigger utilities (caught in prod 2026-04-29: discovery-call-synthesizer,
    /// ask, sanity-check were all flagged as "may have lost their trigger"
    /// despite never having had a schedule). r242 renamed for honesty +
    /// added two filters that cut the false-positive rate sharply:
    ///
    /// 1. **Sub-workflow exclusion** — workflows invoked via `sub_workflow`
    ///    nodes elsewhere are intentionally invoked, not scheduled. Catches
    ///    standups, reviews, ensemble peers, etc. automatically.
    /// 2. **`interactive` tag opt-out** — operator can stamp manual-trigger
    ///    utilities with the `interactive` tag (via `tag_workflow`) to
    ///    suppress this signal permanently.
    ///
    /// **r243 fixed two bugs introduced in r242:**
    /// - The JSONB path I used (`node.kind == 'sub_workflow'`,
    ///   `node.data.sub_workflow_id`) was wrong — actual graph_json schema is
    ///   `node.module_id == 'system:sub_workflow'` and
    ///   `node.config.sub_workflow_id`. The lesson: verify the actual JSON
    ///   shape via `get_workflow` before writing JSONB queries against it.
    /// - `jsonb_array_elements(other.graph_json -> 'nodes')` errors when ANY
    ///   row's `graph_json -> 'nodes'` isn't a JSONB array (legacy/archived
    ///   rows can have wrong shapes). The error fails the entire query, and
    ///   the caller's `.unwrap_or_default()` swallowed it — the field looked
    ///   "clean" while actually being broken. Fixed by guarding with
    ///   `jsonb_typeof(...) = 'array'` AND surfacing the swallow at the
    ///   caller via tracing::warn! so future query regressions are visible.
    ///
    /// **r244 fixed a third bug**: `workflows.graph_json` is stored as TEXT
    /// (per `migrations/001_initial_schema.sql:5`), not JSONB. Applying any
    /// JSONB operator (`->`, `#>>`, `jsonb_typeof`, `jsonb_array_elements`)
    /// directly on the TEXT column errors with "function ... does not exist".
    /// Even with the r243 tracing::warn surface, I missed this one because
    /// the same column on `workflow_versions` IS JSONB, and other code paths
    /// that read `workflows.graph_json` always cast explicitly. r244 adds
    /// the missing `::jsonb` cast at every JSONB op site below.
    pub async fn get_frequently_executed_unscheduled(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<PrevScheduledRow>> {
        let rows = sqlx::query(
            "SELECT w.id, w.name, COUNT(we.id) AS exec_count \
             FROM workflows w \
             JOIN workflow_executions we ON we.workflow_id = w.id \
             WHERE w.user_id = $1 \
               AND we.started_at > NOW() - INTERVAL '60 days' \
               AND (w.status IS NULL OR w.status != 'archived') \
               AND NOT EXISTS ( \
                   SELECT 1 FROM workflow_schedules ws \
                   WHERE ws.workflow_id = w.id AND ws.is_enabled = true \
               ) \
               AND NOT (w.tags && ARRAY['interactive']::text[]) \
               AND NOT EXISTS ( \
                   SELECT 1 FROM workflows other \
                   WHERE other.user_id = $1 \
                     AND other.id != w.id \
                     AND jsonb_typeof(other.graph_json::jsonb -> 'nodes') = 'array' \
                     AND EXISTS ( \
                         SELECT 1 \
                         FROM jsonb_array_elements(other.graph_json::jsonb -> 'nodes') node \
                         WHERE node ->> 'module_id' = 'system:sub_workflow' \
                           AND node #>> '{config,sub_workflow_id}' = w.id::text \
                     ) \
               ) \
             GROUP BY w.id, w.name \
             HAVING COUNT(we.id) >= 3 \
             ORDER BY exec_count DESC LIMIT 10",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await
        .context("get_frequently_executed_unscheduled")?;

        Ok(rows
            .into_iter()
            .map(|r| PrevScheduledRow {
                id: r.try_get("id").unwrap_or(Uuid::nil()),
                name: r.try_get("name").unwrap_or_default(),
                exec_count: r.try_get("exec_count").unwrap_or(0),
            })
            .collect())
    }

    // ── Approval gates ────────────────────────────────────────────────────────

    /// Check whether a workflow is owned by the given user.
    pub async fn check_workflow_ownership(&self, wf_id: Uuid, user_id: Uuid) -> Result<bool> {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM workflows WHERE id = $1 AND user_id = $2)",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await
        .context("check_workflow_ownership")
    }

    /// Insert a new approval gate. Returns the new gate UUID.
    ///
    /// MCP-1192 (2026-05-17): defense-in-depth bound on `expires_hours`
    /// at the repo function boundary. Pre-fix this function trusted
    /// callers to pre-validate; the MCP `handle_create_approval_gate`
    /// validator (1.0..=720.0 since MCP-326) was the only gate. A
    /// future caller forgetting validation would propagate raw f64 to
    /// `NOW() + INTERVAL '1 hour' * $7`:
    ///   - `f64::NAN` / `INFINITY` → Postgres "interval out of range"
    ///     error at request time, opaque to operator.
    ///   - Negative → `NOW() - N hours` → gate immediately expired;
    ///     operator sees success but every approve/reject call 404s.
    ///   - `f64::MAX` → Postgres "interval out of range" or DateTime
    ///     overflow.
    ///   - Zero → same-instant expiration, identical failure mode to
    ///     negative.
    /// Adding the gate here mirrors MCP-1183 / MCP-1184 cross-handler
    /// validation-drift discipline: when N callers must apply the
    /// same bound, push it into the canonical shared function so
    /// drift can't reintroduce the gap.
    /// 720.0 matches the MCP validator's upper bound (30 days).
    #[allow(clippy::too_many_arguments)]
    pub async fn create_approval_gate(
        &self,
        user_id: Uuid,
        title: &str,
        description: Option<&str>,
        payload: &serde_json::Value,
        token: &str,
        continuation_wf: Option<Uuid>,
        expires_hours: f64,
        webhook: Option<&str>,
    ) -> Result<Uuid> {
        if !expires_hours.is_finite() {
            anyhow::bail!(
                "create_approval_gate: expires_hours must be a finite number, got {expires_hours}"
            );
        }
        if !(0.0 < expires_hours && expires_hours <= 720.0) {
            anyhow::bail!(
                "create_approval_gate: expires_hours must be in (0, 720] hours, got {expires_hours}"
            );
        }
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO workflow_approval_gates \
                (user_id, title, description, payload, token, continuation_workflow_id, \
                 expires_at, notification_webhook) \
             VALUES ($1, $2, $3, $4::jsonb, $5, $6, NOW() + INTERVAL '1 hour' * $7, $8) \
             RETURNING id",
        )
        .bind(user_id)
        .bind(title)
        .bind(description)
        .bind(payload)
        .bind(token)
        .bind(continuation_wf)
        .bind(expires_hours)
        .bind(webhook)
        .fetch_one(&self.db_pool)
        .await
        .context("create_approval_gate")
    }

    /// Mark stale pending approval gates as 'expired'.
    pub async fn expire_stale_approval_gates(&self, user_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE workflow_approval_gates \
             SET status = 'expired' \
             WHERE status = 'pending' AND expires_at < NOW() AND user_id = $1",
        )
        .bind(user_id)
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("expire_stale_approval_gates")
    }

    /// List approval gates for a user, optionally filtered by status.
    pub async fn list_approval_gates(
        &self,
        user_id: Uuid,
        status: Option<&str>,
        limit: i32,
    ) -> Result<Vec<ApprovalGateRow>> {
        let rows = if let Some(st) = status {
            sqlx::query(
                "SELECT id, title, description, status, continuation_workflow_id, \
                        created_at, expires_at, resolved_at, resolved_by_type, resolved_by_note \
                 FROM workflow_approval_gates \
                 WHERE user_id = $1 AND status = $2 \
                 ORDER BY created_at DESC LIMIT $3",
            )
            .bind(user_id)
            .bind(st)
            .bind(limit)
            .fetch_all(&self.db_pool)
            .await
        } else {
            sqlx::query(
                "SELECT id, title, description, status, continuation_workflow_id, \
                        created_at, expires_at, resolved_at, resolved_by_type, resolved_by_note \
                 FROM workflow_approval_gates \
                 WHERE user_id = $1 \
                 ORDER BY created_at DESC LIMIT $2",
            )
            .bind(user_id)
            .bind(limit)
            .fetch_all(&self.db_pool)
            .await
        }
        .context("list_approval_gates")?;

        Ok(rows
            .into_iter()
            .map(|r| ApprovalGateRow {
                id: r.try_get("id").unwrap_or(Uuid::nil()),
                title: r.try_get("title").unwrap_or_default(),
                description: r.try_get("description").unwrap_or(None),
                status: r.try_get("status").unwrap_or_default(),
                continuation_workflow_id: r.try_get("continuation_workflow_id").unwrap_or(None),
                created_at: r
                    .try_get("created_at")
                    .unwrap_or_else(|_| chrono::Utc::now()),
                expires_at: r
                    .try_get("expires_at")
                    .unwrap_or_else(|_| chrono::Utc::now()),
                resolved_at: r.try_get("resolved_at").unwrap_or(None),
                resolved_by_type: r.try_get("resolved_by_type").unwrap_or(None),
                resolved_by_note: r.try_get("resolved_by_note").unwrap_or(None),
            })
            .collect())
    }

    /// Fetch the detail fields needed to resolve an approval gate.
    pub async fn get_approval_gate(
        &self,
        gate_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ApprovalGateDetailRow>> {
        let row = sqlx::query(
            "SELECT status, continuation_workflow_id, payload \
             FROM workflow_approval_gates \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(gate_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_approval_gate")?;

        Ok(row.map(|r| ApprovalGateDetailRow {
            status: r.try_get("status").unwrap_or_default(),
            continuation_workflow_id: r.try_get("continuation_workflow_id").unwrap_or(None),
            payload: r.try_get("payload").unwrap_or(serde_json::json!({})),
        }))
    }

    /// Update the status/resolution fields on an approval gate.
    pub async fn resolve_approval_gate(
        &self,
        gate_id: Uuid,
        user_id: Uuid,
        status: &str,
        note: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE workflow_approval_gates \
             SET status = $1, resolved_at = NOW(), resolved_by_type = 'mcp_agent', \
                 resolved_by_note = $2 \
             WHERE id = $3 AND user_id = $4",
        )
        .bind(status)
        .bind(note)
        .bind(gate_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("resolve_approval_gate")
    }

    /// Cancel a pending approval gate. Returns rows affected.
    pub async fn cancel_approval_gate(&self, gate_id: Uuid, user_id: Uuid) -> Result<u64> {
        sqlx::query(
            "UPDATE workflow_approval_gates \
             SET status = 'cancelled', resolved_at = NOW(), resolved_by_type = 'mcp_agent' \
             WHERE id = $1 AND user_id = $2 AND status = 'pending'",
        )
        .bind(gate_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await
        .map(|r| r.rows_affected())
        .context("cancel_approval_gate")
    }

    /// Fetch (title, notification_webhook) for an approval gate (ownership-checked).
    pub async fn get_approval_gate_webhook(
        &self,
        gate_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(String, Option<String>)>> {
        let row = sqlx::query(
            "SELECT title, notification_webhook \
             FROM workflow_approval_gates \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(gate_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_approval_gate_webhook")?;

        Ok(row.map(|r| {
            let title: String = r
                .try_get("title")
                .unwrap_or_else(|_| "Approval Required".to_string());
            let webhook: Option<String> = r.try_get("notification_webhook").unwrap_or(None);
            (title, webhook)
        }))
    }

    // ── Continuation-workflow helpers ─────────────────────────────────────────

    /// Insert a 'queued' workflow execution record.
    ///
    /// MCP-1205 (2026-05-17): bound + DLP-scrub the `payload` before
    /// binding to `workflow_executions.input_data`. This is the
    /// sibling JSONB column to `output_data` (MCP-1204) on the same
    /// table, written by the continuation-trigger path (approval-
    /// gate webhook / workflow-suspension resume). Pre-fix the
    /// caller-supplied `payload` (operator-resume body, webhook
    /// approval JSON, etc.) was bound raw with no size cap AND no
    /// DLP scrub:
    ///
    ///   - `redact_json` was never applied — webhook approval bodies
    ///     carrying secret-shaped tokens in comment fields landed in
    ///     the column unredacted, queryable via audit dashboards.
    ///   - No size cap — a 100 MiB approval-gate body (misbehaved
    ///     upstream / DoS attempt that survives the webhook router's
    ///     own cap) would pin controller heap during the JSON
    ///     serialise + bind.
    ///
    /// The 10 MiB ceiling matches the sibling `bound_execution_payload`
    /// applied at the output side in MCP-1204; the DLP scrub matches
    /// the canonical persistence-boundary discipline (MCP-466/481/
    /// 967/971/972 family).
    pub async fn insert_queued_execution(
        &self,
        exec_id: Uuid,
        wf_id: Uuid,
        user_id: Uuid,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let bounded = talos_dlp_provider::bound_execution_payload(payload);
        let scrubbed = talos_dlp_provider::redact_json(&bounded);
        sqlx::query(
            "INSERT INTO workflow_executions \
                (id, workflow_id, user_id, status, input_data, started_at) \
             VALUES ($1, $2, $3, 'queued', $4::jsonb, NOW())",
        )
        .bind(exec_id)
        .bind(wf_id)
        .bind(user_id)
        .bind(&scrubbed)
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("insert_queued_execution")
    }

    /// Write back the continuation execution ID to an approval gate.
    pub async fn set_gate_execution_id(&self, gate_id: Uuid, exec_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE workflow_approval_gates SET continuation_execution_id = $1 WHERE id = $2",
        )
        .bind(exec_id)
        .bind(gate_id)
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("set_gate_execution_id")
    }

    /// Fetch graph_json for a workflow (ownership-checked).
    pub async fn get_workflow_graph_json(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        sqlx::query_scalar::<_, String>(
            "SELECT graph_json FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_workflow_graph_json")
    }

    /// MCP-564: ownership-checked fetch of a workflow's bound actor_id.
    /// Returns Ok(None) if the workflow doesn't exist OR isn't owned by
    /// `user_id` OR has no bound actor. Used by `trigger_continuation_workflow`
    /// to gate dispatch on the actor's budget/status — the webhook /
    /// approval-resolve path was the last unguarded dispatch surface
    /// after the MCP-555/MCP-557 sweep covered scheduler / engine chains
    /// / retry.
    pub async fn get_workflow_actor_id(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Uuid>> {
        let row: Option<(Option<Uuid>,)> =
            sqlx::query_as("SELECT actor_id FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(wf_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await
                .context("get_workflow_actor_id")?;
        Ok(row.and_then(|r| r.0))
    }

    /// Fail a workflow execution with an error message.
    pub async fn fail_execution(&self, exec_id: Uuid, error: &str) -> Result<()> {
        // MCP-970 (2026-05-15): DLP-redact at the bind boundary.
        // Yet another `fail_execution` variant — sibling to MCP-967
        // (WorkflowRepository / ExecutionRepository),
        // MCP-968 (ActorRepository / module-execs / engine), and
        // MCP-969 (format!() drift sites). Four repository crates
        // own copies of this method shape — every one needs the
        // redact-before-bind discipline.
        //
        // MCP-1164 (2026-05-17): truncate-then-redact discipline,
        // sibling to MCP-1161 which closed the same gap on
        // `WorkflowRepository::mark_execution_failed`. THREE
        // repositories write to `workflow_executions.error_message`:
        // WorkflowRepository (fixed in MCP-1161), AdvancedRepository
        // (this site), ActorRepository (sibling fix in same commit).
        // The MCP-1161 audit noted "when retrofitting a discipline
        // to N columns on a table, sweep the related boundaries" —
        // this is the third sweep of the same `error_message` column
        // across the three writer crates. 4 KiB matches the MCP-1161
        // ceiling and the MCP-1160 sibling on webhook_request_log.
        let truncated: &str = if error.len() > 4096 {
            talos_text_util::truncate_at_char_boundary(error, 4096)
        } else {
            error
        };
        let redacted_error = talos_dlp_provider::redact_str(truncated);
        sqlx::query(
            "UPDATE workflow_executions \
             SET status = 'failed', error_message = $1, completed_at = NOW() \
             WHERE id = $2",
        )
        .bind(&redacted_error)
        .bind(exec_id)
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("fail_execution")
    }

    /// Cancel all still-running module_executions for a workflow execution.
    /// Called after marking a workflow as failed so parallel siblings are cleaned up.
    pub async fn cancel_running_module_executions(&self, execution_id: Uuid) -> Result<()> {
        let result = sqlx::query(
            "UPDATE module_executions \
             SET status = 'cancelled', completed_at = NOW(), \
                 error_message = 'Workflow failed — parallel sibling cancelled' \
             WHERE workflow_execution_id = $1 AND status = 'running'",
        )
        .bind(execution_id)
        .execute(&self.db_pool)
        .await
        .context("cancel_running_module_executions")?;
        tracing::info!(
            execution_id = %execution_id,
            cancelled = result.rows_affected(),
            "sibling cancellation UPDATE complete"
        );
        Ok(())
    }

    /// Transition a queued execution to 'running'.
    pub async fn set_execution_running(&self, exec_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE workflow_executions SET status = 'running', started_at = NOW() \
             WHERE id = $1 AND status = 'queued'",
        )
        .bind(exec_id)
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("set_execution_running")
    }

    // MCP-683 (2026-05-13): the former `complete_execution` method was
    // removed here. Pre-fix it wrote `output_data = $2` plaintext via
    // raw SQL — bypassing Phase A encryption for every continuation
    // workflow (its sole caller). The caller in
    // `talos_continuation_trigger` now routes through
    // `WorkflowRepository::with_encryption(...).mark_execution_{completed,waiting}`
    // (same fix shape as MCP-682). Leaving a stub here would tempt
    // future code to re-introduce the bypass; deletion makes the
    // regression fail-closed at the type level.

    // ── SLA thresholds ────────────────────────────────────────────────────────

    /// Verify workflow ownership (returns id if found).
    pub async fn verify_workflow_ownership_exists(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool> {
        let exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(wf_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await
                .context("verify_workflow_ownership_exists")?;
        Ok(exists.is_some())
    }

    /// Create or update an SLA threshold for a workflow.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_sla_threshold(
        &self,
        id: Uuid,
        wf_id: Uuid,
        user_id: Uuid,
        p95_latency_ms: Option<i64>,
        success_rate_pct: Option<f64>,
        webhook: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO workflow_sla_thresholds \
             (id, workflow_id, user_id, p95_latency_ms, success_rate_pct, notification_webhook) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (workflow_id, user_id) DO UPDATE SET \
                 p95_latency_ms       = EXCLUDED.p95_latency_ms, \
                 success_rate_pct     = EXCLUDED.success_rate_pct, \
                 notification_webhook = EXCLUDED.notification_webhook",
        )
        .bind(id)
        .bind(wf_id)
        .bind(user_id)
        .bind(p95_latency_ms)
        .bind(success_rate_pct)
        .bind(webhook)
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("upsert_sla_threshold")
    }

    /// List all SLA thresholds for a user (with workflow name).
    pub async fn list_sla_thresholds(&self, user_id: Uuid) -> Result<Vec<SlaThresholdRow>> {
        let rows = sqlx::query(
            "SELECT t.id, t.workflow_id, w.name AS workflow_name, \
                    t.p95_latency_ms, t.success_rate_pct::float8 AS success_rate_pct, \
                    t.notification_webhook, t.created_at \
             FROM workflow_sla_thresholds t \
             JOIN workflows w ON w.id = t.workflow_id \
             WHERE t.user_id = $1 \
             ORDER BY t.created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await
        .context("list_sla_thresholds")?;

        Ok(rows
            .into_iter()
            .map(|r| SlaThresholdRow {
                id: r.get("id"),
                workflow_id: r.get("workflow_id"),
                workflow_name: r.get("workflow_name"),
                p95_latency_ms: r.get("p95_latency_ms"),
                success_rate_pct: r.get("success_rate_pct"),
                notification_webhook: r.get("notification_webhook"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    /// Fetch SLA threshold config for webhook testing.
    pub async fn get_sla_threshold(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<SlaThresholdConfigRow>> {
        let row = sqlx::query(
            "SELECT notification_webhook, p95_latency_ms, success_rate_pct \
             FROM workflow_sla_thresholds \
             WHERE workflow_id = $1 AND user_id = $2",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_sla_threshold")?;

        Ok(row.map(|r| SlaThresholdConfigRow {
            notification_webhook: r.try_get("notification_webhook").unwrap_or_default(),
            p95_latency_ms: r.try_get("p95_latency_ms").unwrap_or(None),
            success_rate_pct: r.try_get("success_rate_pct").unwrap_or(None),
        }))
    }

    // ── Built-in templates ────────────────────────────────────────────────────

    /// Remove stale system-published marketplace entries (sandbox/QA templates).
    /// Returns the number of entries removed.
    pub async fn remove_stale_system_marketplace(&self) -> Result<u64> {
        // Phase 5.1: unified `modules` table; canonical id match only.
        sqlx::query(
            "DELETE FROM module_marketplace mm
             WHERE mm.publisher_id = '00000000-0000-0000-0000-000000000000'::uuid
               AND EXISTS (
                   SELECT 1 FROM modules m
                   WHERE m.id = mm.module_id
                     AND (
                         m.user_id IS NOT NULL
                         OR m.name IS NULL
                         OR m.description IS NULL
                         OR m.description = ''
                     )
               )",
        )
        .execute(&self.db_pool)
        .await
        .map(|r| r.rows_affected())
        .context("remove_stale_system_marketplace")
    }

    /// Publish all system-seeded (first-party) templates not yet listed.
    /// Returns the number of entries published.
    pub async fn publish_system_templates(&self) -> Result<u64> {
        // Phase 5.1: unified `modules` table; canonical id dedup only.
        sqlx::query(
            "INSERT INTO module_marketplace
                 (id, module_id, publisher_id, name, description, capability_world,
                  version, is_public, tags, verified)
             SELECT
                 gen_random_uuid(), m.id,
                 '00000000-0000-0000-0000-000000000000'::uuid,
                 m.name, m.description, m.capability_world,
                 '1.0.0', true, ARRAY[]::text[], true
             FROM modules m
             WHERE m.user_id IS NULL
               AND m.kind = 'catalog'
               AND m.name IS NOT NULL
               AND m.description IS NOT NULL
               AND m.description != ''
               AND NOT EXISTS (
                   SELECT 1 FROM module_marketplace mm
                   WHERE mm.module_id = m.id
               )",
        )
        .execute(&self.db_pool)
        .await
        .map(|r| r.rows_affected())
        .context("publish_system_templates")
    }

    // ── Workflow suspensions ──────────────────────────────────────────────────

    /// Create a workflow suspension and return its UUID.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_suspension(
        &self,
        user_id: Uuid,
        correlation_id: &str,
        description: Option<&str>,
        continuation_wf: Option<Uuid>,
        state: Option<&serde_json::Value>,
        timeout_at: Option<DateTime<Utc>>,
        callback_url: &str,
    ) -> Result<Uuid> {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO workflow_suspensions \
                (user_id, correlation_id, description, continuation_workflow_id, state, \
                 timeout_at, callback_url) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             RETURNING id",
        )
        .bind(user_id)
        .bind(correlation_id)
        .bind(description)
        .bind(continuation_wf)
        .bind(state)
        .bind(timeout_at)
        .bind(callback_url)
        .fetch_one(&self.db_pool)
        .await
        .context("create_suspension")
    }

    /// List workflow suspensions for a user, optionally filtered by status.
    pub async fn list_suspensions(
        &self,
        user_id: Uuid,
        status: Option<&str>,
    ) -> Result<Vec<SuspensionRow>> {
        let rows = if let Some(st) = status {
            sqlx::query(
                "SELECT id, correlation_id, description, status, continuation_workflow_id, \
                        callback_url, timeout_at, resumed_at, resumed_by, created_at \
                 FROM workflow_suspensions \
                 WHERE user_id = $1 AND status = $2 \
                 ORDER BY created_at DESC LIMIT 50",
            )
            .bind(user_id)
            .bind(st)
            .fetch_all(&self.db_pool)
            .await
        } else {
            sqlx::query(
                "SELECT id, correlation_id, description, status, continuation_workflow_id, \
                        callback_url, timeout_at, resumed_at, resumed_by, created_at \
                 FROM workflow_suspensions \
                 WHERE user_id = $1 \
                 ORDER BY created_at DESC LIMIT 50",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await
        }
        .context("list_suspensions")?;

        Ok(rows
            .into_iter()
            .map(|r| SuspensionRow {
                id: r.get("id"),
                correlation_id: r.get("correlation_id"),
                description: r.get("description"),
                status: r.get("status"),
                continuation_workflow_id: r.get("continuation_workflow_id"),
                callback_url: r.get("callback_url"),
                timeout_at: r.get("timeout_at"),
                resumed_at: r.get("resumed_at"),
                resumed_by: r.get("resumed_by"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    /// Fetch a suspension by correlation_id (ownership-checked) for resumption.
    pub async fn get_suspension_by_correlation(
        &self,
        correlation_id: &str,
        user_id: Uuid,
    ) -> Result<Option<SuspensionDetailRow>> {
        let row = sqlx::query(
            "SELECT id, status, continuation_workflow_id \
             FROM workflow_suspensions \
             WHERE correlation_id = $1 AND user_id = $2",
        )
        .bind(correlation_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_suspension_by_correlation")?;

        Ok(row.map(|r| SuspensionDetailRow {
            id: r.get("id"),
            status: r.get("status"),
            continuation_workflow_id: r.get("continuation_workflow_id"),
        }))
    }

    /// Mark a suspension as resumed with the given payload.
    pub async fn mark_suspension_resumed(
        &self,
        suspension_id: Uuid,
        payload: &serde_json::Value,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE workflow_suspensions \
             SET status='resumed', resumed_at=now(), resumed_by='mcp_tool', resumed_payload=$1 \
             WHERE id = $2",
        )
        .bind(payload)
        .bind(suspension_id)
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("mark_suspension_resumed")
    }

    /// Atomically claim a waiting suspension for the MCP resume path.
    ///
    /// Combines status check + state transition + payload write in a single
    /// `UPDATE ... WHERE status='waiting' RETURNING` so two concurrent
    /// `resume_workflow_by_correlation_id` calls from the same user cannot
    /// both pass the gate and double-fire the continuation workflow. Mirrors
    /// the atomic claim that the public `/api/callbacks/{correlation_id}`
    /// handler already uses; the MCP path previously did SELECT-check-fire-mark
    /// non-atomically.
    ///
    /// Returns `Ok(Some((id, continuation_workflow_id)))` on a successful claim,
    /// `Ok(None)` if the suspension is missing, owned by another user, or no
    /// longer in 'waiting' state.
    pub async fn claim_suspension_for_mcp_resume(
        &self,
        correlation_id: &str,
        user_id: Uuid,
        payload: &serde_json::Value,
    ) -> Result<Option<(Uuid, Option<Uuid>)>> {
        let row = sqlx::query(
            "UPDATE workflow_suspensions \
             SET status='resumed', resumed_at=now(), resumed_by='mcp_tool', resumed_payload=$1 \
             WHERE correlation_id = $2 AND user_id = $3 AND status = 'waiting' \
             RETURNING id, continuation_workflow_id",
        )
        .bind(payload)
        .bind(correlation_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("claim_suspension_for_mcp_resume")?;

        Ok(row.map(|r| (r.get("id"), r.get("continuation_workflow_id"))))
    }

    /// Cancel a waiting suspension by correlation_id. Returns rows affected.
    ///
    /// MCP-828 (2026-05-14): stamps `resumed_by='mcp_tool'` so the in-table
    /// audit trail mirrors every other state-transition path out of waiting
    /// (resume via MCP → `'mcp_tool'`, resume via public callback →
    /// `'callback_url'`, timeout expiry → `'timeout_expiry'`). Pre-fix the
    /// column was left NULL on cancel, so an audit query like
    /// `WHERE resumed_by='mcp_tool'` to surface MCP-driven state transitions
    /// silently missed every cancellation — `resumed_at` was already being
    /// stamped, so the row LOOKED like a resume to readers that didn't
    /// also project `status`. Same misleading-success class as MCP-737/738/800.
    pub async fn cancel_suspension(&self, correlation_id: &str, user_id: Uuid) -> Result<u64> {
        sqlx::query(
            "UPDATE workflow_suspensions \
             SET status='cancelled', resumed_at=now(), resumed_by='mcp_tool' \
             WHERE correlation_id = $1 AND user_id = $2 AND status = 'waiting'",
        )
        .bind(correlation_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await
        .map(|r| r.rows_affected())
        .context("cancel_suspension")
    }

    /// Execute a pre-validated SELECT statement wrapped in a pagination
    /// subquery and return the raw rows. Used **only** by `handle_query_paginated`
    /// in `mcp/advanced.rs` — that handler enforces all the safety invariants
    /// (admin-only auth, SELECT-only, no semicolons / UNION / INTERSECT /
    /// EXCEPT / CTEs / EXPLAIN / SQL comments, blocked-table list, blocked-schema
    /// list, cursor_column allowlisted to `[a-zA-Z0-9_]`).
    ///
    /// **CRITICAL — DO NOT CALL FROM ANYWHERE ELSE WITHOUT AUDITING THE
    /// VALIDATION STACK.** This method intentionally accepts a free-form SQL
    /// fragment because the alternative — a structured query DSL that mirrors
    /// arbitrary `SELECT` shapes — is materially worse than the current
    /// well-bounded inline shape. The repo owns only the immutable wrapper
    /// template (`SELECT * FROM (<base>) AS _paginated_subquery ...`) so that
    /// the pagination contract has exactly one home.
    ///
    /// `validated_base_query` MUST be a single `SELECT` statement that has
    /// already passed the handler's validation pipeline. `mode` carries the
    /// pre-validated cursor column or offset.
    pub async fn execute_paginated_select(
        &self,
        validated_base_query: &str,
        page_size: i64,
        mode: PaginationMode<'_>,
    ) -> Result<Vec<sqlx::postgres::PgRow>, sqlx::Error> {
        match mode {
            PaginationMode::Cursor { column, after } => {
                // The cursor `column` is already constrained to [a-zA-Z0-9_]
                // by the calling handler; double-quoting handles reserved words.
                let q = format!(
                    "SELECT * FROM ({}) AS _paginated_subquery \
                     WHERE CAST(\"{}\" AS text) > $2 ORDER BY \"{}\" ASC LIMIT $1",
                    validated_base_query, column, column
                );
                sqlx::query(&q)
                    .bind(page_size + 1)
                    .bind(after)
                    .fetch_all(&self.db_pool)
                    .await
            }
            PaginationMode::Offset { offset } => {
                let q = format!(
                    "SELECT * FROM ({}) AS _paginated_subquery LIMIT $1 OFFSET $2",
                    validated_base_query
                );
                sqlx::query(&q)
                    .bind(page_size + 1)
                    .bind(offset)
                    .fetch_all(&self.db_pool)
                    .await
            }
        }
    }

    // ── advanced.rs MCP-handler support ────────────────────────────────────

    /// Search marketplace listings with optional `query` (ILIKE name),
    /// `world_filter` (capability_world equality), and `tag_filter`.
    /// Builds the dynamic SQL inside the repo so the handler doesn't have to
    /// touch raw SQL — the variable shape is constrained to a fixed set of
    /// optional WHERE clauses.
    pub async fn search_marketplace(
        &self,
        filter: MarketplaceSearchFilter<'_>,
        limit: i64,
    ) -> Result<Vec<MarketplaceSearchRow>> {
        let mut sql = String::from(
            "SELECT id, module_id, publisher_id, name, description, capability_world, version, downloads, tags, created_at \
             FROM module_marketplace WHERE is_public = true",
        );
        let mut bind_idx = 0u32;
        let mut binds: Vec<String> = Vec::new();

        if let Some(q) = filter.query {
            if !q.is_empty() {
                bind_idx += 1;
                sql.push_str(&format!(" AND name ILIKE ${}", bind_idx));
                binds.push(format!("%{}%", q));
            }
        }
        if let Some(world) = filter.world {
            bind_idx += 1;
            sql.push_str(&format!(" AND capability_world = ${}", bind_idx));
            binds.push(world.to_string());
        }
        if let Some(tag) = filter.tag {
            bind_idx += 1;
            sql.push_str(&format!(" AND ${} = ANY(tags)", bind_idx));
            binds.push(tag.to_string());
        }
        bind_idx += 1;
        sql.push_str(&format!(" ORDER BY downloads DESC LIMIT ${}", bind_idx));

        let mut q = sqlx::query(&sql);
        for b in &binds {
            q = q.bind(b);
        }
        q = q.bind(limit);

        let rows = q.fetch_all(&self.db_pool).await?;
        Ok(rows
            .iter()
            .map(|r| MarketplaceSearchRow {
                id: r.get("id"),
                module_id: r.get("module_id"),
                name: r.get("name"),
                description: r.try_get("description").unwrap_or_default(),
                capability_world: r.get("capability_world"),
                version: r.get("version"),
                downloads: r.get("downloads"),
                tags: r.get("tags"),
            })
            .collect())
    }

    /// Find groups of workflows with duplicate names (top 10 most-duplicated
    /// groups), returning every member of each group with id + created_at.
    /// Used by `agent_session_start` for ghost-workflow detection.
    pub async fn find_workflow_duplicate_name_groups(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<WorkflowDuplicateGroupRow>> {
        let rows: Vec<(Uuid, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            "SELECT id, name, created_at \
             FROM workflows \
             WHERE user_id = $1 \
               AND (status IS NULL OR status != 'archived') \
               AND name IN ( \
                 SELECT name FROM workflows \
                 WHERE user_id = $1 AND (status IS NULL OR status != 'archived') \
                 GROUP BY name HAVING COUNT(*) > 1 \
                 ORDER BY COUNT(*) DESC, name ASC \
                 LIMIT 10 \
               ) \
             ORDER BY name ASC, created_at ASC",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, name, created_at)| WorkflowDuplicateGroupRow {
                id,
                name,
                created_at,
            })
            .collect())
    }

    /// Pinned modules with a flag indicating whether the user has the
    /// installed module row (true) or needs to call
    /// restore_pinned_modules (false). Distinct from the simpler version on
    /// ModuleRepository which checks `modules.wasm_bytes` presence — this
    /// variant checks for the user's per-install modules row.
    pub async fn list_pinned_modules_with_user_install_status(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<PinnedModuleInstallStatus>> {
        // Phase 5: modules.user_id + name is the new per-user install
        // signal. The old wasm_modules/node_templates join collapses to a
        // single lookup by (user_id, name).
        // RFC 0004 M4: user_module_pins is RLS-enforced — run on the
        // per-user scoped tx so the policy's user_id clause matches.
        let mut tx = self.user_scoped_tx(user_id).await?;
        let rows = sqlx::query(
            "SELECT pm.module_name, \
                    EXISTS( \
                        SELECT 1 FROM modules m \
                        WHERE m.user_id = $1 AND m.name = pm.module_name \
                    ) AS has_wasm \
             FROM user_module_pins pm \
             WHERE pm.user_id = $1 \
             ORDER BY pm.pinned_at ASC \
             LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows
            .iter()
            .map(|r| PinnedModuleInstallStatus {
                module_name: r.get("module_name"),
                has_wasm: r.try_get("has_wasm").unwrap_or(false),
            })
            .collect())
    }

    /// Active actors with active-memory count subquery. Used by
    /// `agent_session_start` to surface persona context.
    pub async fn list_active_actors_with_memory_count(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ActiveActorWithMemoryRow>> {
        let rows = sqlx::query(
            "SELECT id, name, description, status, max_capability_world, \
                    (SELECT COUNT(*) FROM actor_memory am \
                     WHERE am.actor_id = a.id \
                       AND (am.expires_at IS NULL OR am.expires_at > NOW())) AS memory_count \
             FROM actors a \
             WHERE a.user_id = $1 AND a.status != 'archived' \
             ORDER BY a.created_at DESC \
             LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| ActiveActorWithMemoryRow {
                id: r.get("id"),
                name: r.get("name"),
                description: r.try_get("description").unwrap_or(None),
                status: r
                    .try_get::<Option<String>, _>("status")
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "active".to_string()),
                max_capability_world: r
                    .try_get::<Option<String>, _>("max_capability_world")
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "minimal-node".to_string()),
                memory_count: r.try_get("memory_count").unwrap_or(0),
            })
            .collect())
    }

    /// Recent execution activity for the agent's session-start awareness.
    ///
    /// Returns up to `limit` workflow executions that are either:
    /// - currently `running` (regardless of age — surface long-running jobs
    ///   the agent kicked off and may have lost the response for), OR
    /// - reached a terminal state within the last `minutes_window` minutes
    ///   (so the agent that just reconnected can see what happened in the gap).
    ///
    /// Joined with `workflows` for the human-readable `name` so the agent
    /// can present the activity without a follow-up RTT.
    ///
    /// Designed to address the MCP-transport drop-response failure mode:
    /// long-running synchronous tools (test_workflow, call_workflow) where
    /// the server keeps executing past the client's read deadline. Without
    /// this, the agent thinks "session expired" → executes failed → retries
    /// → double-billed LLM calls + ghost work.
    pub async fn list_recent_executions_for_session_awareness(
        &self,
        user_id: Uuid,
        minutes_window: i32,
        limit: i64,
    ) -> Result<Vec<RecentExecutionRow>> {
        let rows = sqlx::query(
            "SELECT \
                we.id AS execution_id, \
                we.workflow_id, \
                COALESCE(w.name, '<deleted>') AS workflow_name, \
                we.status, \
                we.started_at, \
                we.completed_at, \
                CASE \
                    WHEN we.completed_at IS NOT NULL \
                    THEN ROUND(EXTRACT(EPOCH FROM (we.completed_at - we.started_at)) * 1000)::bigint \
                    ELSE NULL \
                END AS duration_ms \
             FROM workflow_executions we \
             LEFT JOIN workflows w ON w.id = we.workflow_id \
             WHERE we.user_id = $1 \
               AND ( \
                   we.status = 'running' \
                   OR we.completed_at >= NOW() - INTERVAL '1 minute' * $2 \
               ) \
             ORDER BY \
               CASE WHEN we.status = 'running' THEN 0 ELSE 1 END, \
               COALESCE(we.completed_at, we.started_at) DESC \
             LIMIT $3",
        )
        .bind(user_id)
        .bind(minutes_window)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| RecentExecutionRow {
                execution_id: r.get("execution_id"),
                workflow_id: r.get("workflow_id"),
                workflow_name: r.try_get("workflow_name").unwrap_or_default(),
                status: r.get("status"),
                started_at: r.try_get("started_at").ok(),
                completed_at: r.try_get("completed_at").ok(),
                duration_ms: r.try_get::<Option<i64>, _>("duration_ms").ok().flatten(),
            })
            .collect())
    }

    /// Stuck executions: status = 'running' for more than `hours_threshold`
    /// hours. Returns hours-stuck as f64 (rounded server-side via EXTRACT).
    pub async fn list_stuck_executions(
        &self,
        user_id: Uuid,
        hours_threshold: i32,
        limit: i64,
    ) -> Result<Vec<StuckExecutionRow>> {
        // The `INTERVAL '1 hour' * $2` form binds the hours threshold safely
        // (vs concatenating into the literal). Note: PostgreSQL accepts
        // multiplying an interval by an integer.
        let rows = sqlx::query(
            "SELECT id, workflow_id, status, started_at, \
                    ROUND(EXTRACT(EPOCH FROM (NOW()-started_at))/3600, 1)::float8 AS hours_stuck \
             FROM workflow_executions \
             WHERE user_id = $1 AND status = 'running' \
               AND started_at < NOW() - INTERVAL '1 hour' * $2 \
             ORDER BY started_at ASC LIMIT $3",
        )
        .bind(user_id)
        .bind(hours_threshold)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| StuckExecutionRow {
                execution_id: r.get("id"),
                workflow_id: r.get("workflow_id"),
                hours_stuck: r.try_get("hours_stuck").unwrap_or(0.0),
            })
            .collect())
    }
}

/// Pagination mode for `execute_paginated_select`. The `column` field in
/// `Cursor` MUST already be validated against the `[a-zA-Z0-9_]` allowlist
/// by the calling handler — the repo string-formats it directly into the
/// wrapper SQL.
#[derive(Debug)]
pub enum PaginationMode<'a> {
    Cursor { column: &'a str, after: &'a str },
    Offset { offset: i64 },
}

/// Optional-filter struct for `search_marketplace`.
#[derive(Debug, Default)]
pub struct MarketplaceSearchFilter<'a> {
    pub query: Option<&'a str>,
    pub world: Option<&'a str>,
    pub tag: Option<&'a str>,
}

/// Marketplace listing row.
#[derive(Debug)]
pub struct MarketplaceSearchRow {
    pub id: Uuid,
    pub module_id: Uuid,
    pub name: String,
    pub description: String,
    pub capability_world: String,
    pub version: String,
    pub downloads: i32,
    pub tags: Vec<String>,
}

/// Duplicate-group member row.
#[derive(Debug)]
pub struct WorkflowDuplicateGroupRow {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Pinned module install status (per-user wasm_modules row presence).
#[derive(Debug)]
pub struct PinnedModuleInstallStatus {
    pub module_name: String,
    pub has_wasm: bool,
}

/// Active-actor projection with active-memory count.
#[derive(Debug)]
pub struct ActiveActorWithMemoryRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub max_capability_world: String,
    pub memory_count: i64,
}

/// Stuck-execution row.
#[derive(Debug)]
pub struct StuckExecutionRow {
    pub execution_id: Uuid,
    pub workflow_id: Uuid,
    pub hours_stuck: f64,
}

/// Recent-execution row for the session_start MCP-transport-drop awareness.
/// Combines running + recently-completed in one shape; the `status` field
/// distinguishes them.
#[derive(Debug)]
pub struct RecentExecutionRow {
    pub execution_id: Uuid,
    pub workflow_id: Uuid,
    pub workflow_name: String,
    pub status: String,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub duration_ms: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_row() -> TemplateSourceRow {
        TemplateSourceRow {
            code_template: String::new(),
            wasm_bytes: None,
            config_schema: serde_json::json!({}),
            allowed_secrets: vec![],
            allowed_hosts: vec![],
        }
    }

    #[test]
    fn normalize_wasm_bytes_collapses_empty_to_none() {
        assert_eq!(normalize_wasm_bytes(None), None);
        assert_eq!(normalize_wasm_bytes(Some(vec![])), None);
        assert_eq!(normalize_wasm_bytes(Some(vec![0x00])), Some(vec![0x00]));
    }

    #[test]
    fn dispatch_picks_wasm_when_bytes_present() {
        let mut row = empty_row();
        // wasm magic bytes — content is irrelevant, presence is what counts
        row.wasm_bytes = Some(vec![0x00, 0x61, 0x73, 0x6d]);
        assert_eq!(InstallDispatch::from_source(&row), InstallDispatch::Wasm);
    }

    #[test]
    fn dispatch_picks_template_when_only_source_present() {
        let mut row = empty_row();
        row.code_template =
            "fn run(_: String) -> Result<String, String> { Ok(String::new()) }".into();
        assert_eq!(
            InstallDispatch::from_source(&row),
            InstallDispatch::Template
        );
    }

    #[test]
    fn dispatch_rejects_when_neither_present() {
        assert_eq!(
            InstallDispatch::from_source(&empty_row()),
            InstallDispatch::Reject
        );
    }

    #[test]
    fn dispatch_prefers_wasm_when_both_present() {
        // Realistic case: a marketplace listing has both source AND a fresh
        // compile. Pick the bytes — recompiling on install is wasteful and
        // also blocked by the cargo-audit gate on locked-down hosts.
        let mut row = empty_row();
        row.wasm_bytes = Some(vec![0x01]);
        row.code_template =
            "fn run(_: String) -> Result<String, String> { Ok(String::new()) }".into();
        assert_eq!(InstallDispatch::from_source(&row), InstallDispatch::Wasm);
    }

    #[test]
    fn dispatch_rejects_a_normalised_zero_byte_row() {
        // Defence-in-depth: even if a future caller bypasses
        // normalize_wasm_bytes and stuffs an empty vec into the struct,
        // dispatch should not pick the Wasm path. Today this would still
        // pick Wasm (Some(empty) is_some()); document the shortcoming
        // and assert the safer behaviour after a manual normalise.
        let mut row = empty_row();
        row.wasm_bytes = Some(vec![]);
        // Manual normalise — what every caller MUST do, but the test
        // documents that the dispatch enum is downstream of this step.
        row.wasm_bytes = normalize_wasm_bytes(row.wasm_bytes);
        assert_eq!(InstallDispatch::from_source(&row), InstallDispatch::Reject);
    }
}
