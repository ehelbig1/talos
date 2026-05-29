//! GraphQL Mutation resolvers (MutationRoot).

use async_graphql::{Context, Object, Result};
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;

#[allow(unused_imports)]
use crate::schema::types::*;
use crate::schema::{require_2fa, require_scope, SafeErrorExtensions};
// Removed unused imports: CompilationService, ParallelWorkflowEngine, encrypt_checkpoint

#[derive(Default)]
pub struct WebhooksMutations;

#[Object]
impl WebhooksMutations {
    async fn create_webhook_trigger(
        &self,
        ctx: &Context<'_>,
        input: CreateWebhookTriggerInput,
    ) -> Result<WebhookTrigger> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WebhooksAccess)?;

        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;
        // MCP-631: empty-env hardening.
        let base_url = talos_config::get_base_url();

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        // Verify the user owns the module.
        // Phase 5.1: unified `modules` table by canonical id.
        let module_exists: Option<bool> = sqlx::query_scalar(
            "SELECT EXISTS( \
                 SELECT 1 FROM modules \
                 WHERE id = $1 \
                   AND user_id = $2 \
             )",
        )
        .bind(input.module_id)
        .bind(user_id)
        .fetch_one(db_pool)
        .await?;

        if !module_exists.unwrap_or(false) {
            // MCP-918: .extend_safe()
            return Err(async_graphql::Error::new(
                "Module not found or access denied",
            ).extend_safe());
        }

        // MCP-832 (2026-05-14): MCP-769 sweep — replace shallow length-only
        // check with focused content-discipline via `validate_display_name`
        // (trim + reject empty-after-trim + length cap + control-char /
        // `\0` rejection). Pre-fix `name: "   "` persisted as literal
        // whitespace and rendered as a blank entry in the webhooks
        // dashboard; `name: "evil\0name"` later crashed UPDATE operations
        // with opaque Postgres errors (MCP-431).
        let trimmed_name = crate::schema::validate_display_name(
            "Webhook trigger name",
            &input.name,
            255,
        )?;
        let name = trimmed_name.to_string();

        let enabled = input.enabled.unwrap_or(true);
        // Convert Option<Vec<String>> to Option<&[String]> without extra allocation.
        let allowed_ips = input.allowed_ips.as_deref();

        // Validate IP addresses/CIDRs
        if let Some(ips) = allowed_ips {
            if let Err(e) = talos_rate_limit::IpWhitelist::from_string(&ips.join(",")) {
                return Err({
                    tracing::error!("Invalid allowed IPs: {}", e);
                    async_graphql::Error::new("Invalid allowed IPs").extend_safe()
                });
            }
        }

        // Enforce minimum HMAC signing secret length to prevent weak secrets.
        // MCP-749 (2026-05-13): mirror the MCP `handle_create_webhook_trigger`
        // content discipline at `talos-mcp-handlers/src/webhooks.rs:275`.
        // Pre-fix the GraphQL surface only enforced `len >= 32` — leaving
        // two real holes:
        //   * Whitespace-only secrets (e.g. 32 spaces) passed the length
        //     check, persisted into `webhook_triggers.signing_secret_enc`
        //     as the literal whitespace string, and silently broke
        //     inbound HMAC verification forever — the operator only
        //     noticed when every inbound webhook returned 401 and the
        //     stored secret value looked plausible on a list query.
        //   * No upper bound — an unbounded signing_secret bloats every
        //     `webhook_triggers` row and inflates the per-request HMAC
        //     compute cost on the dispatch path; MCP caps at 1024.
        // GraphQL keeps the stricter 32-char minimum (dashboard convention
        // — see verification_token comment below); the MCP path settles
        // for 16. Both paths now reject whitespace-only and cap at 1024.
        if let Some(ref secret) = input.signing_secret {
            let trimmed = secret.trim();
            if trimmed.is_empty() {
                return Err(async_graphql::Error::new(
                    "Webhook signing_secret must be a non-empty, non-whitespace string when provided. \
                     Omit the field for static-token auth.",
                )
                .extend_safe());
            }
            if secret.len() < 32 {
                return Err(async_graphql::Error::new(
                    "Webhook signing secret must be at least 32 characters",
                )
                .extend_safe());
            }
            if secret.len() > 1024 {
                return Err(async_graphql::Error::new(
                    "Webhook signing_secret must be ≤ 1024 characters",
                )
                .extend_safe());
            }
        }

        // MCP-724 (2026-05-13): enforce minimum length on caller-supplied
        // verification_token. Pre-fix the GraphQL surface accepted ANY
        // length (including 1-char tokens) while the auto-generated
        // default below uses 64 hex chars (256 bits of entropy). A
        // self-foot-gun in spirit (the caller controls their own
        // webhook's auth strength), but the platform's minimum-length
        // policy on `signing_secret` (32 chars) above sets the
        // convention — the static-fallback verification path
        // (`talos-webhooks/src/lib.rs:653`) authenticates inbound
        // requests on this token via `subtle::ConstantTimeEq`, so a
        // 1-char token is brute-forceable in seconds from any source IP
        // (within the per-IP rate limit, but the cap is ~100 req/min,
        // making a 36-attempt sweep finish in <1 min). The MCP-side
        // handler (`talos-mcp-handlers/src/webhooks.rs:376`) always
        // overwrites caller input with a fresh `Uuid::new_v4()` (36
        // chars), so this gap was GraphQL-only.
        // MCP-871 (2026-05-14): full content discipline on
        // verification_token. Pre-fix this gate only enforced the 32-char
        // floor — leaving three holes that paralleled the MCP-749
        // signing_secret sweep but on the sibling auth field:
        //   * 32 spaces passed (whitespace-only token persisted into
        //     `webhook_triggers.verification_token` as 32 literal spaces;
        //     the `subtle::ConstantTimeEq` verification still works
        //     bytewise, but the stored value is meaningless on read).
        //   * No upper bound — a 10 MB token would bloat every row and
        //     inflate per-request HMAC compute on dispatch. signing_secret
        //     caps at 1024; this should match.
        //   * `\0` / control chars on the original were accepted — same
        //     MCP-431 class as the broader content-discipline sweep,
        //     and a NUL in the verification_token can crash downstream
        //     UPDATE/string-render paths.
        // MCP-side handler auto-generates a fresh Uuid, so this is a
        // GraphQL-only gap.
        if let Some(ref token) = input.verification_token {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                return Err(async_graphql::Error::new(
                    "Webhook verification_token must be a non-empty, non-whitespace string \
                     when provided. Omit the field to generate a 64-char random token.",
                )
                .extend_safe());
            }
            if token.len() < 32 {
                return Err(async_graphql::Error::new(
                    "Webhook verification_token must be at least 32 characters when supplied. \
                     Omit the field to generate a 64-char random token.",
                )
                .extend_safe());
            }
            if token.len() > 1024 {
                return Err(async_graphql::Error::new(
                    "Webhook verification_token must be ≤ 1024 characters",
                )
                .extend_safe());
            }
            talos_validation::reject_control_chars(
                "Webhook verification_token",
                token,
                talos_validation::LineMode::MultiLine,
            )
            .map_err(|e| async_graphql::Error::new(e.message).extend_safe())?;
        }

        // MCP-812 (2026-05-14): validate caller-supplied
        // max_requests_per_minute. Pre-fix the value was bound straight
        // into Postgres via `.unwrap_or(100)` with NO bounds check. The
        // column is `INTEGER` (signed i32), so `Some(-1)` was accepted
        // and persisted as -1. The runtime rate-limiter
        // (`talos-webhooks/src/lib.rs:482`) then casts via
        // `trigger.max_requests_per_minute as usize` — on 64-bit
        // platforms `-1i32 as usize` underflows to 18446744073709551615,
        // which the token-bucket interprets as "unlimited burst
        // capacity". A malicious caller could thus self-bypass the
        // operator-intended per-webhook rate limit (sibling pattern to
        // MCP-767 / MCP-811: caller-supplied negatives slipping past
        // upper-only `.min()` clamps). Aggregate per-user limit
        // (`TALOS_WEBHOOK_USER_RPM`, default 300) is still enforced at
        // the second token bucket so blast radius is bounded, but the
        // per-trigger control surface should still mean what it says.
        //
        // Bounds: [1, 10_000] — below 1 is meaningless (just disable
        // the webhook), 10_000 rpm ≈ 166 rps is well above any
        // legitimate operator notification target (Slack / PagerDuty /
        // OpsGenie typically max out at ~100 rpm) and provides
        // headroom for high-throughput internal services.
        if let Some(rpm) = input.max_requests_per_minute {
            if !(1..=10_000).contains(&rpm) {
                return Err(async_graphql::Error::new(format!(
                    "Webhook max_requests_per_minute must be in [1, 10000] when supplied (got {}). \
                     Omit the field to use the default of 100 rpm.",
                    rpm
                ))
                .extend_safe());
            }
        }
        let rpm_resolved = input.max_requests_per_minute.unwrap_or(100);

        // Generate verification token if not provided
        let verification_token = input.verification_token.unwrap_or_else(|| {
            use rand::RngCore;
            let mut random_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut random_bytes);
            hex::encode(random_bytes)
        });

        // MCP-S2: pre-generate the trigger id so we can bind it as AAD
        // into the AES-GCM tag at encrypt time. Without this binding,
        // an attacker with DB write access can swap another row's
        // `signing_secret_enc` onto this trigger and forge HMAC-signed
        // payloads. The pre-generated UUID is then bound INSERT-time
        // so the encrypt-time AAD and the persisted row id are
        // guaranteed identical.
        let trigger_id = Uuid::new_v4();

        // Encrypt signing secret at rest using envelope encryption (AES-256-GCM).
        // The plaintext signing_secret column is set to NULL; only the encrypted
        // column is populated for new triggers.
        let secrets_manager = ctx.data::<Arc<talos_secrets_manager::SecretsManager>>()?;
        let (signing_secret_enc, signing_key_id, signing_secret_format) =
            if let Some(ref secret) = input.signing_secret {
                let (key_id, encrypted, version) = secrets_manager
                    .encrypt_value_aad_v1(secret, trigger_id.as_bytes())
                    .await
                    .map_err(|e| {
                        tracing::error!("Failed to encrypt webhook signing_secret: {}", e);
                        async_graphql::Error::new("Failed to secure signing secret").extend_safe()
                    })?;
                (Some(encrypted), Some(key_id), version)
            } else {
                // No signing secret → no ciphertext to version, but we
                // persist v1 anyway so the column's invariant ("v1 means
                // the row was written by post-MCP-S2 code") is uniform.
                (None, None, talos_secrets_manager::SecretsManager::AAD_FORMAT_V1)
            };

        let listener_id = sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO webhook_triggers (
                id, name, module_id, verification_token,
                signing_secret_enc, signing_key_id, signing_secret_format,
                max_requests_per_minute, enabled, allowed_ips, user_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id
            "#,
        )
        .bind(trigger_id)
        .bind(&name)
        .bind(input.module_id)
        .bind(&verification_token)
        .bind(signing_secret_enc.as_deref())
        .bind(signing_key_id)
        .bind(signing_secret_format)
        .bind(rpm_resolved)
        .bind(enabled)
        .bind(allowed_ips)
        .bind(user_id)
        .fetch_one(db_pool)
        .await?;

        Ok(WebhookTrigger {
            id: listener_id,
            module_id: Some(input.module_id),
            name,
            webhook_url: format!("{}/webhooks/{}", base_url, listener_id),
            verification_token: Some(verification_token), // Return token on creation
            enabled,
            max_requests_per_minute: rpm_resolved,
            trigger_count: 0,
            success_count: 0,
            error_count: 0,
            last_triggered_at: None,
        })
    }

    async fn replay_webhook_dead_letter_entry(&self, ctx: &Context<'_>, id: Uuid) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // Fetch entry — verify ownership via trigger's user_id.
        // MCP-675 (2026-05-13): pre-fix the WHERE clause was
        // `(t.user_id = $2 OR d.trigger_id IS NULL)`. The OR-IS-NULL
        // branch let ANY user fetch DLQ entries whose trigger had been
        // deleted (the webhook_triggers FK is `ON DELETE SET NULL`, so
        // orphaned rows are common after a trigger delete). The handler
        // body refuses to actually replay null-trigger entries — it
        // bails at line ~185 with "DLQ entry has no associated trigger"
        // — but the SELECT path still leaks two bits of info per probe:
        // (a) whether a DLQ ID exists at all (200 vs 404 timing), and
        // (b) whether `replayed_at` is set (different error message at
        // line ~177). Both leakages let user_B enumerate user_A's
        // orphaned-DLQ state. The SAFE shape removes the OR branch
        // entirely: an orphaned DLQ entry is inaccessible until an
        // operator (with admin tooling) cleans it up. UX cost is
        // accepted — losing trigger ownership shouldn't promote a row
        // to cross-tenant readable.
        #[derive(sqlx::FromRow)]
        struct DlqRow {
            trigger_id: Option<Uuid>,
            payload: Option<serde_json::Value>,
            replayed_at: Option<chrono::DateTime<chrono::Utc>>,
        }
        let row = sqlx::query_as::<_, DlqRow>(
            r#"
            SELECT d.trigger_id, d.payload, d.replayed_at
            FROM webhook_dlq d
            INNER JOIN webhook_triggers t ON t.id = d.trigger_id
            WHERE d.id = $1 AND t.user_id = $2
            "#,
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(db_pool)
        .await
        .map_err(|e| e.extend_safe())?
        .ok_or_else(|| async_graphql::Error::new("DLQ entry not found").extend_safe())?;

        if row.replayed_at.is_some() {
            return Err(async_graphql::Error::new("Entry has already been replayed").extend_safe());
        }

        let Some(trigger_id) = row.trigger_id else {
            return Err(
                async_graphql::Error::new("DLQ entry has no associated trigger").extend_safe(),
            );
        };

        // Re-dispatch via WebhookRouter
        let webhook_router = ctx
            .data::<std::sync::Arc<talos_webhooks::WebhookRouter>>()
            .map_err(|_| async_graphql::Error::new("Webhook router unavailable").extend_safe())?;

        let payload_bytes = row
            .payload
            .as_ref()
            .map(|v| serde_json::to_vec(v).unwrap_or_default())
            .unwrap_or_default();

        webhook_router
            .dispatch_replay(trigger_id, payload_bytes)
            .await
            .map_err(|e| {
                tracing::error!(dlq_id = %id, "DLQ replay failed: {}", e);
                async_graphql::Error::new("Replay failed").extend_safe()
            })?;

        // Mark replayed
        sqlx::query("UPDATE webhook_dlq SET replayed_at = now(), replayed_by = $1 WHERE id = $2")
            .bind(user_id)
            .bind(id)
            .execute(db_pool)
            .await
            .map_err(|e| e.extend_safe())?;

        Ok(true)
    }

    async fn replay_dead_letter_entry(&self, ctx: &Context<'_>, id: Uuid) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        // MCP-826 (2026-05-14): wire the actual engine re-dispatch.
        //
        // Pre-fix this handler only marked the DLQ row `replayed_at`
        // — there was NO engine call, NO new workflow_execution row,
        // NO re-fire. The frontend `DLQViewer.tsx` "Replay" button
        // displayed a misleading-success toast ("Protocol job replayed
        // successfully") while nothing actually replayed. Operators
        // relying on this for incident recovery would assume the
        // failed workflow had been re-run when it hadn't.
        //
        // Same misleading-success-via-mutation-result class as MCP-825
        // (`rotateEncryptionKey` was a no-op masquerading as a real
        // rotation). The MCP-725 comment that lived here documented
        // the gap as "not yet implemented" but the mutation kept
        // returning `Ok(true)` like a real replay — operators have no
        // way to distinguish "you successfully kicked off a replay"
        // from "you got an audit row but nothing actually ran."
        //
        // Fix: extend the SELECT to fetch `execution_id`, then call
        // `ExecutionOrchestrationService::replay` (the same service
        // backing the MCP `replay_execution` tool — advisory-lock-
        // protected actor budget gate, full trigger-time
        // capability-ceiling re-verification per MCP-707, fresh
        // execution row with `parent_execution_id` lineage). Mark the
        // DLQ row replayed only AFTER the engine accepts the replay,
        // so a dispatcher failure surfaces as Err to the caller
        // instead of phantom-marking the row.
        #[derive(sqlx::FromRow)]
        struct DlqRow {
            execution_id: Uuid,
            replayed_at: Option<chrono::DateTime<chrono::Utc>>,
        }
        let row: DlqRow = sqlx::query_as::<_, DlqRow>(
            "SELECT d.execution_id, d.replayed_at \
             FROM dead_letter_queue d \
             JOIN workflows w ON w.id = d.workflow_id \
             WHERE d.id = $1 AND w.user_id = $2",
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(db_pool)
        .await
        .map_err(|e| e.extend_safe())?
        .ok_or_else(|| {
            async_graphql::Error::new("DLQ entry not found or access denied").extend_safe()
        })?;

        if row.replayed_at.is_some() {
            return Err(
                async_graphql::Error::new("Entry has already been replayed").extend_safe(),
            );
        }

        // Dispatch the real replay via the shared service. Same Arc
        // backing the MCP path; the engine creates a fresh execution
        // row with `parent_execution_id` lineage.
        let orchestration_service = ctx
            .data::<std::sync::Arc<talos_execution_orchestration::ExecutionOrchestrationService>>()
            .map_err(|_| {
                async_graphql::Error::new(
                    "Execution orchestration service unavailable — cannot replay",
                )
                .extend_safe()
            })?;

        let outcome = orchestration_service
            .replay(talos_execution_orchestration::ReplayInput {
                original_execution_id: row.execution_id,
                user_id,
                replay_agent_id: None,
            })
            .await
            .map_err(|e| {
                tracing::error!(
                    user_id = %user_id,
                    dlq_id = %id,
                    original_execution_id = %row.execution_id,
                    "DLQ replay dispatch failed: {}",
                    e
                );
                async_graphql::Error::new("Replay dispatch failed").extend_safe()
            })?;

        // Only mark replayed AFTER the engine accepted the dispatch.
        // Operator semantics: replayed_at = "we successfully kicked
        // off a new execution," NOT "we wrote a timestamp."
        sqlx::query(
            "UPDATE dead_letter_queue \
             SET replayed_at = NOW(), replayed_by = $1 \
             WHERE id = $2",
        )
        .bind(user_id)
        .bind(id)
        .execute(db_pool)
        .await
        .map_err(|e| e.extend_safe())?;

        info!(
            user_id = %user_id,
            dlq_id = %id,
            original_execution_id = %row.execution_id,
            new_execution_id = %outcome.execution_id,
            "Dead letter entry replayed — new execution dispatched"
        );

        Ok(true)
    }
}
