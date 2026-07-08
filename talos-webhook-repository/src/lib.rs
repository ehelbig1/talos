//! WebhookRepository — centralises SQL for the `webhook_triggers` and
//! `webhook_request_log` tables. Handlers in `mcp/webhooks.rs` should be thin
//! wrappers over these methods.

use anyhow::{Context, Result};
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub struct WebhookRepository {
    db_pool: PgPool,
}

/// One webhook row returned by the listing helpers.
#[derive(Debug)]
pub struct WebhookListRow {
    pub id: Uuid,
    pub name: String,
    /// NULL for workflow-bound webhooks (`workflow_id` set instead) —
    /// `webhook_triggers.module_id` is nullable by design. Pre-fix this
    /// was a bare `Uuid`, so `row.get` PANICKED on the first
    /// workflow-bound webhook and every `list_webhooks` call after it
    /// died with a connection reset (found live, regression round 3
    /// 2026-07-08).
    pub module_id: Option<Uuid>,
    pub enabled: bool,
    pub max_requests_per_minute: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// RFC 0007: the trigger's event filter, if any (NULL = fire on every
    /// verified delivery). Surfaced read-only so operators can confirm what
    /// they set; evaluated server-side in `talos_webhooks::event_filter_matches`.
    pub event_filter: Option<serde_json::Value>,
}

/// Stats-bearing webhook row for the GraphQL `webhook_triggers` listing
/// (fire counters + last-fired, no created_at). Counter columns are nullable
/// in the schema (DEFAULT 0 from 001) — COALESCEd in the query.
#[derive(Debug, sqlx::FromRow)]
pub struct WebhookTriggerStatsRow {
    pub id: Uuid,
    pub name: String,
    pub module_id: Option<Uuid>,
    pub enabled: bool,
    pub max_requests_per_minute: i32,
    pub trigger_count: i32,
    pub success_count: i32,
    pub error_count: i32,
    pub last_triggered_at: Option<chrono::DateTime<chrono::Utc>>,
    pub event_filter: Option<serde_json::Value>,
}

/// Webhook DLQ entry, owner-scoped through the trigger JOIN. `source_ip` /
/// `headers` / `payload` arrive pre-cast to text (INET/JSONB columns); the
/// payload/headers were DLP-scrubbed before storage.
#[derive(Debug, sqlx::FromRow)]
pub struct WebhookDlqRow {
    pub id: Uuid,
    pub trigger_id: Option<Uuid>,
    pub source_ip: Option<String>,
    pub drop_reason: String,
    pub headers: Option<String>,
    pub payload: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub replayed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub replayed_by: Option<Uuid>,
}

/// Webhook-DLQ replay target (trigger id + raw JSONB payload + replay
/// marker) returned by `get_dlq_entry_for_replay`. Ownership is enforced
/// by the INNER JOIN on the trigger's `user_id` — orphaned entries
/// (trigger deleted, FK SET NULL) are deliberately inaccessible (MCP-675).
#[derive(Debug, sqlx::FromRow)]
pub struct WebhookDlqReplayRow {
    pub trigger_id: Option<Uuid>,
    pub payload: Option<serde_json::Value>,
    pub replayed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Insert params for the GraphQL `createWebhookTrigger` mutation. The
/// signing secret arrives PRE-encrypted — the resolver owns the AAD
/// binding to the pre-generated trigger `id` (MCP-S2 swap-resistance);
/// this repository method only persists the ciphertext + key id.
pub struct NewWebhookTrigger<'a> {
    pub id: Uuid,
    pub name: &'a str,
    pub module_id: Uuid,
    pub verification_token: &'a str,
    pub signing_secret_enc: Option<&'a [u8]>,
    pub signing_key_id: Option<Uuid>,
    pub signing_secret_format: i16,
    pub max_requests_per_minute: i32,
    pub enabled: bool,
    pub allowed_ips: Option<&'a [String]>,
    pub user_id: Uuid,
    pub event_filter: Option<&'a serde_json::Value>,
}

/// 24-hour security stats per webhook trigger. Used by
/// `get_webhook_security_stats`.
#[derive(Debug)]
pub struct WebhookSecurityStat {
    pub trigger_id: Uuid,
    pub trigger_name: Option<String>,
    pub auth_failures: i64,
    pub rate_limit_hits: i64,
    pub successes: i64,
}

impl WebhookRepository {
    pub fn new(db_pool: PgPool) -> Self {
        Self { db_pool }
    }

    /// True if a webhook with this name already exists for the user. Used as
    /// a pre-flight check by `create_webhook` because there is no DB-level
    /// unique constraint on `webhook_triggers.name`.
    pub async fn name_exists_for_user(&self, name: &str, user_id: Uuid) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM webhook_triggers WHERE name = $1 AND user_id = $2)",
        )
        .bind(name)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(exists)
    }

    /// MCP-686 (2026-05-13): the caller-level cap-check + insert flow
    /// was TOCTOU-vulnerable. Two concurrent `create_webhook` calls
    /// for the same user each saw the cap-1 count via separate
    /// transactions, both passed the gate, both INSERTed — leaving
    /// the user one over the cap (compounding under burst). Closed by
    /// folding the count + insert into one transaction under a
    /// per-user advisory lock (same shape as MCP-685 on api-keys).
    ///
    /// Returns:
    /// - `Ok(None)` if the user is already at or over the cap;
    /// - `Ok(Some(current_count_pre_insert))` on successful insert.
    ///
    /// Caller MUST pass exactly one of `module_id` (single-module fire) or
    /// `workflow_id` (full-workflow fire). When `signing_secret` is provided,
    /// it is envelope-encrypted via `SecretsManager::encrypt_value` (done
    /// OUTSIDE the transaction so the per-user advisory lock isn't held
    /// across the slow KMS round-trip).
    #[allow(clippy::too_many_arguments)]
    pub async fn try_create_under_cap(
        &self,
        webhook_id: Uuid,
        user_id: Uuid,
        name: &str,
        module_id: Option<Uuid>,
        workflow_id: Option<Uuid>,
        verification_token: &str,
        max_requests_per_minute: i32,
        auto_respond: bool,
        sync_timeout_secs: i32,
        signing_secret: Option<&str>,
        // RFC 0007: pre-validated event filter (the caller validates shape via
        // `talos_webhooks::validate_event_filter` — this method only persists
        // it, so the repository crate stays free of a dep on talos-webhooks).
        // None → NULL → fire on every verified delivery.
        event_filter: Option<&serde_json::Value>,
        secrets_manager: &talos_secrets_manager::SecretsManager,
        cap: i64,
    ) -> Result<Option<i64>> {
        // MCP-S2: envelope-encrypt the optional signing secret with AAD
        // bound to the pre-generated webhook_id, so an attacker with DB
        // write capability can't swap another row's signing_secret_enc
        // onto this trigger and forge HMAC payloads. Failure here MUST
        // surface — silently dropping the secret would leave the caller
        // thinking HMAC is enabled when it isn't. Done BEFORE the
        // transaction so the advisory lock is held for milliseconds, not
        // seconds.
        let (signing_secret_enc, signing_key_id, signing_secret_format): (
            Option<Vec<u8>>,
            Option<Uuid>,
            i16,
        ) = match signing_secret {
            Some(s) if !s.is_empty() => {
                let (key_id, ciphertext, version) = secrets_manager
                    .encrypt_value_aad_v3(s, webhook_id.as_bytes())
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to encrypt webhook signing_secret: {}", e)
                    })?;
                (Some(ciphertext), Some(key_id), version)
            }
            _ => (
                None,
                None,
                talos_secrets_manager::SecretsManager::AAD_FORMAT_V1,
            ),
        };

        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("Failed to begin webhook create transaction")?;

        // Per-user advisory lock. 42939990001 — distinct salt from
        // MCP-685's api-keys salt so the two subsystems don't block
        // each other.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 42939990001))")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .context("Failed to acquire per-user advisory lock")?;

        let current: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM webhook_triggers WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&mut *tx)
                .await
                .context("Failed to count webhooks under cap lock")?;

        if current >= cap {
            // Transaction rolls back on drop, releasing the advisory lock.
            return Ok(None);
        }

        sqlx::query(
            "INSERT INTO webhook_triggers \
             (id, user_id, name, module_id, workflow_id, verification_token, \
              max_requests_per_minute, auto_respond, sync_response, sync_timeout_secs, \
              signing_secret_enc, signing_key_id, signing_secret_format, event_filter, enabled, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, true, NOW())",
        )
        .bind(webhook_id)
        .bind(user_id)
        .bind(name)
        .bind(module_id)
        .bind(workflow_id)
        .bind(verification_token)
        .bind(max_requests_per_minute)
        .bind(auto_respond)
        // sync_response mirrors auto_respond — both flags are needed for the
        // webhook router to actually wait for + return the inline result.
        .bind(auto_respond)
        .bind(sync_timeout_secs)
        .bind(signing_secret_enc.as_deref())
        .bind(signing_key_id)
        .bind(signing_secret_format)
        .bind(event_filter)
        .execute(&mut *tx)
        .await
        .context("Failed to insert webhook under cap lock")?;

        tx.commit()
            .await
            .context("Failed to commit webhook create transaction")?;

        Ok(Some(current))
    }

    /// Persist a webhook trigger for the GraphQL `createWebhookTrigger`
    /// mutation (no per-user cap gate — that flow belongs to
    /// `try_create_under_cap`, the MCP path). Returns the inserted row id.
    pub async fn insert_trigger(&self, t: NewWebhookTrigger<'_>) -> Result<Uuid> {
        let id = sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO webhook_triggers (
                id, name, module_id, verification_token,
                signing_secret_enc, signing_key_id, signing_secret_format,
                max_requests_per_minute, enabled, allowed_ips, user_id, event_filter
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING id
            "#,
        )
        .bind(t.id)
        .bind(t.name)
        .bind(t.module_id)
        .bind(t.verification_token)
        .bind(t.signing_secret_enc)
        .bind(t.signing_key_id)
        .bind(t.signing_secret_format)
        .bind(t.max_requests_per_minute)
        .bind(t.enabled)
        .bind(t.allowed_ips)
        .bind(t.user_id)
        .bind(t.event_filter)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(id)
    }

    /// Fetch a webhook-DLQ entry for replay, ownership-gated via the
    /// INNER JOIN on the trigger's `user_id`. Orphaned entries (trigger
    /// deleted → FK SET NULL) don't match the JOIN and are inaccessible
    /// until operator cleanup — losing trigger ownership must not promote
    /// a row to cross-tenant readable (MCP-675).
    pub async fn get_dlq_entry_for_replay(
        &self,
        dlq_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WebhookDlqReplayRow>> {
        let row = sqlx::query_as::<_, WebhookDlqReplayRow>(
            "SELECT d.trigger_id, d.payload, d.replayed_at \
             FROM webhook_dlq d \
             INNER JOIN webhook_triggers t ON t.id = d.trigger_id \
             WHERE d.id = $1 AND t.user_id = $2",
        )
        .bind(dlq_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row)
    }

    /// Stamp a webhook-DLQ entry as replayed. Ownership was established by
    /// the preceding `get_dlq_entry_for_replay` read; this write keys on id
    /// alone (matching the pre-extraction resolver SQL).
    pub async fn mark_dlq_entry_replayed(&self, dlq_id: Uuid, replayed_by: Uuid) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE webhook_dlq SET replayed_at = now(), replayed_by = $1 WHERE id = $2",
        )
        .bind(replayed_by)
        .bind(dlq_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// List a user's webhooks (most recent first, capped at `limit`).
    pub async fn list_for_user(&self, user_id: Uuid, limit: i64) -> Result<Vec<WebhookListRow>> {
        let rows = sqlx::query(
            "SELECT id, name, module_id, enabled, max_requests_per_minute, created_at, event_filter \
             FROM webhook_triggers WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter().map(row_to_webhook).collect()
    }

    /// Paginated stats listing for the GraphQL `webhook_triggers` query.
    /// User-scoped by predicate; unique `id DESC` tiebreaker keeps OFFSET
    /// pages stable.
    pub async fn list_for_user_with_stats(
        &self,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<WebhookTriggerStatsRow>> {
        let rows = sqlx::query_as::<_, WebhookTriggerStatsRow>(
            "SELECT id, name, module_id, enabled, max_requests_per_minute, \
                    COALESCE(trigger_count, 0) AS trigger_count, \
                    COALESCE(success_count, 0) AS success_count, \
                    COALESCE(error_count, 0) AS error_count, \
                    last_triggered_at, event_filter \
             FROM webhook_triggers WHERE user_id = $1 \
             ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3",
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    /// Webhook DLQ entries for a user's triggers, newest first. Ownership is
    /// enforced by the JOIN on `webhook_triggers.user_id` (webhook_dlq has no
    /// user column of its own).
    pub async fn list_dlq_for_user(&self, user_id: Uuid, limit: i64) -> Result<Vec<WebhookDlqRow>> {
        let rows = sqlx::query_as::<_, WebhookDlqRow>(
            "SELECT d.id, d.trigger_id, d.source_ip::text AS source_ip, d.drop_reason, \
                    d.headers::text AS headers, d.payload::text AS payload, d.created_at, \
                    d.replayed_at, d.replayed_by \
             FROM webhook_dlq d \
             JOIN webhook_triggers t ON t.id = d.trigger_id \
             WHERE t.user_id = $1 \
             ORDER BY d.created_at DESC \
             LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    /// Delete a webhook scoped to user. Returns rows affected (0 = not
    /// found / not owned).
    pub async fn delete(&self, webhook_id: Uuid, user_id: Uuid) -> Result<u64> {
        let result = sqlx::query("DELETE FROM webhook_triggers WHERE id = $1 AND user_id = $2")
            .bind(webhook_id)
            .bind(user_id)
            .execute(&self.db_pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Toggle a webhook's `enabled` flag.
    pub async fn set_enabled(&self, webhook_id: Uuid, user_id: Uuid, enabled: bool) -> Result<u64> {
        let result =
            sqlx::query("UPDATE webhook_triggers SET enabled = $1 WHERE id = $2 AND user_id = $3")
                .bind(enabled)
                .bind(webhook_id)
                .bind(user_id)
                .execute(&self.db_pool)
                .await?;
        Ok(result.rows_affected())
    }

    /// List webhook triggers attached to any of the given module ids
    /// (scoped to user). Used by `list_workflow_webhooks` after extracting
    /// module ids from the workflow's graph_json.
    pub async fn list_for_modules(
        &self,
        module_ids: &[Uuid],
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<WebhookListRow>> {
        if module_ids.is_empty() {
            return Ok(vec![]);
        }
        let rows = sqlx::query(
            "SELECT id, name, module_id, enabled, max_requests_per_minute, created_at, event_filter \
             FROM webhook_triggers \
             WHERE module_id = ANY($1) AND user_id = $2 \
             ORDER BY created_at DESC LIMIT $3",
        )
        .bind(module_ids)
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter().map(row_to_webhook).collect()
    }

    /// 24-hour aggregate of auth failures, rate-limit hits, and successes per
    /// webhook trigger, scoped to the calling user. Used by
    /// `get_webhook_security_stats`.
    pub async fn get_security_stats_24h(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<WebhookSecurityStat>> {
        let rows = sqlx::query(
            r#"
            SELECT
                wrl.trigger_id,
                wt.name AS trigger_name,
                COUNT(*) FILTER (WHERE wrl.error_message ILIKE '%Invalid signature%'
                                  OR wrl.error_message ILIKE '%Invalid verification token%') AS auth_failures,
                COUNT(*) FILTER (WHERE wrl.error_message ILIKE '%Rate limit exceeded%')    AS rate_limit_hits,
                COUNT(*) FILTER (WHERE wrl.success = true)                                 AS successes
            FROM webhook_request_log wrl
            LEFT JOIN webhook_triggers wt ON wt.id = wrl.trigger_id
            WHERE wrl.created_at >= NOW() - INTERVAL '24 hours'
              AND wt.user_id = $1
            GROUP BY wrl.trigger_id, wt.name
            ORDER BY auth_failures DESC, rate_limit_hits DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<WebhookSecurityStat> {
                Ok(WebhookSecurityStat {
                    trigger_id: r.try_get("trigger_id")?,
                    trigger_name: r.try_get("trigger_name").ok().flatten(),
                    // RFC check-52: fail loud on schema drift (read as Option so a
                    // genuinely-NULL count still yields 0, but a renamed/retyped
                    // column errors instead of silently reporting 0).
                    auth_failures: r.try_get::<Option<_>, _>("auth_failures")?.unwrap_or(0),
                    rate_limit_hits: r.try_get::<Option<_>, _>("rate_limit_hits")?.unwrap_or(0),
                    successes: r.try_get::<Option<_>, _>("successes")?.unwrap_or(0),
                })
            })
            .collect::<Result<Vec<_>>>()
    }
}

/// Fallible row projection (check 55): bare `row.get` PANICS on a NULL or
/// type-drifted column, killing the tokio task mid-request (the caller
/// sees a connection reset — the #427 list_webhooks incident). `try_get`
/// + `?` keeps the fail-loud contract as a clean error instead.
fn row_to_webhook(row: &sqlx::postgres::PgRow) -> Result<WebhookListRow> {
    Ok(WebhookListRow {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        module_id: row.try_get("module_id")?,
        enabled: row.try_get("enabled")?,
        max_requests_per_minute: row.try_get("max_requests_per_minute")?,
        created_at: row.try_get("created_at")?,
        event_filter: row.try_get("event_filter")?,
    })
}
