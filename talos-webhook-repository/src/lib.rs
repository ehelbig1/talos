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
    pub module_id: Uuid,
    pub enabled: bool,
    pub max_requests_per_minute: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
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

    /// List a user's webhooks (most recent first, capped at `limit`).
    pub async fn list_for_user(&self, user_id: Uuid, limit: i64) -> Result<Vec<WebhookListRow>> {
        let rows = sqlx::query(
            "SELECT id, name, module_id, enabled, max_requests_per_minute, created_at \
             FROM webhook_triggers WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows.iter().map(row_to_webhook).collect())
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
            "SELECT id, name, module_id, enabled, max_requests_per_minute, created_at \
             FROM webhook_triggers \
             WHERE module_id = ANY($1) AND user_id = $2 \
             ORDER BY created_at DESC LIMIT $3",
        )
        .bind(module_ids)
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows.iter().map(row_to_webhook).collect())
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
        Ok(rows
            .iter()
            .map(|r| WebhookSecurityStat {
                trigger_id: r.get("trigger_id"),
                trigger_name: r.try_get("trigger_name").ok().flatten(),
                auth_failures: r.try_get("auth_failures").unwrap_or(0),
                rate_limit_hits: r.try_get("rate_limit_hits").unwrap_or(0),
                successes: r.try_get("successes").unwrap_or(0),
            })
            .collect())
    }
}

fn row_to_webhook(row: &sqlx::postgres::PgRow) -> WebhookListRow {
    WebhookListRow {
        id: row.get("id"),
        name: row.get("name"),
        module_id: row.get("module_id"),
        enabled: row.get("enabled"),
        max_requests_per_minute: row.get("max_requests_per_minute"),
        created_at: row.get("created_at"),
    }
}
