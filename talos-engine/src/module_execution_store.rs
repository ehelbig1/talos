//! Postgres-backed [`ModuleExecutionStore`] writing to the
//! `module_executions` table.
//!
//! Owns the "resolve template_id → wasm_modules.id" COALESCE query that
//! used to live inlined in the engine body, plus the two INSERT
//! variants (race-safe single-node vs. simple pipeline-step).
//!
//! Phase A payload encryption: when `with_encryption(secrets)` is
//! called, `record_started` and `record_completed` route their
//! `input` / `output` payloads through
//! `module_payload_encryption::encrypt_payload_bundle` and write
//! ciphertext into `*_enc` columns instead of the legacy plaintext
//! columns. Without the builder call, the store falls back to the
//! pre-Phase-A plaintext write path so tests keep working.

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use talos_workflow_engine_core::{BoxError, ExecutionStartedContext, ModuleExecutionStore};
use uuid::Uuid;

/// Default Talos impl. Holds a Postgres pool + optional SecretsManager
/// for at-rest payload encryption.
pub struct PostgresModuleExecutionStore {
    pool: Pool<Postgres>,
    secrets_manager: Option<Arc<talos_secrets_manager::SecretsManager>>,
}

impl PostgresModuleExecutionStore {
    /// Build a store bound to `pool`. Without `with_encryption`, writes
    /// land in the legacy plaintext columns.
    #[must_use]
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self {
            pool,
            secrets_manager: None,
        }
    }

    /// Builder: attach SecretsManager so input/output payloads encrypt
    /// at rest. Mirrors the `ModuleExecutionService::with_encryption`
    /// pattern so all three writer paths share semantics.
    #[must_use]
    pub fn with_encryption(mut self, sm: Arc<talos_secrets_manager::SecretsManager>) -> Self {
        self.secrets_manager = Some(sm);
        self
    }
}

impl std::fmt::Debug for PostgresModuleExecutionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresModuleExecutionStore")
            .field("pool", &self.pool)
            .finish()
    }
}

#[async_trait]
impl ModuleExecutionStore for PostgresModuleExecutionStore {
    async fn record_started(&self, ctx: ExecutionStartedContext<'_>) -> Result<(), BoxError> {
        let ExecutionStartedContext {
            id,
            module_id,
            user_id,
            workflow_execution_id,
            input,
            trigger_type,
            race_safe_status,
        } = ctx;

        // The race-safe variant uses INSERT...SELECT with a CASE WHEN
        // subquery so the row atomically inherits the parent workflow's
        // current status. If the workflow has already been flipped to
        // 'failed' / 'cancelled' (because a sibling node failed while
        // this INSERT was in-flight), the row enters as 'cancelled'
        // rather than 'running'. Without this, a late-arriving INSERT
        // under concurrent load creates a phantom 'running' row that
        // outlives the workflow.
        //
        // Pipeline steps skip the race-safe path — they're dispatched
        // atomically as a chain and can't race against themselves.
        // Phase A encryption: when SecretsManager is wired, encrypt the
        // input payload at rest. The plaintext column is written as NULL,
        // input_data_enc holds the ciphertext, and payload_enc_key_id
        // points at the DEK. Without the wiring, we fall through to the
        // legacy plaintext write path.
        let bundle = talos_module_payload_encryption::encrypt_payload_bundle(
            self.secrets_manager.as_ref(),
            Some(input),
            None,
            None,
        )
        .await
        .map_err(|e| -> BoxError { e.into() })?;
        // MCP-987 (2026-05-15): DLP-redact the plaintext-fallback path.
        // When encryption is wired (production-default), `pt_input` is
        // None and `input_data_enc` carries the ciphertext. When
        // encryption is unavailable (SecretsManager gap, KMS outage),
        // we fall back to binding plaintext to `input_data` —
        // arbitrary node inputs (webhook bodies, prior-node outputs,
        // trigger payloads) routinely contain secret-shaped values
        // (Bearer tokens, sk-/ghp_ patterns, OAuth callback codes).
        // Without redaction the failure path silently lands raw
        // user data in a queryable column. Same defense-in-depth
        // shape as MCP-971/972/975 on workflow_executions; sibling
        // fix at talos-webhooks/src/lib.rs and at record_completed
        // below.
        let encrypting = bundle.encrypting();
        let redacted_pt_input = if encrypting {
            None
        } else {
            Some(talos_dlp_provider::redact_json(input))
        };
        let pt_input = redacted_pt_input.as_ref();

        let result = if race_safe_status {
            // module_executions has a real top-level trigger_type column
            // (migration 012_node_executions.sql then renamed via
            // 015_rename_tables.sql). The workflow_executions reference
            // in the CASE WHEN sub-query below is a status check
            // against a different table.
            // allow-trigger-type-column: see comment block above.
            sqlx::query(
                "INSERT INTO module_executions \
                 (id, module_id, user_id, status, \
                  input_data, input_data_enc, payload_enc_key_id, \
                  workflow_execution_id, trigger_type, started_at) \
                 SELECT $1, $2, $3, \
                     CASE WHEN EXISTS( \
                         SELECT 1 FROM workflow_executions \
                         WHERE id = $7 AND status IN ('failed', 'cancelled') \
                     ) THEN 'cancelled' ELSE 'running' END, \
                     $4, $5, $6, $7, $8, NOW() \
                 ON CONFLICT DO NOTHING",
            )
            .bind(id)
            .bind(module_id)
            .bind(user_id)
            .bind(pt_input)
            .bind(bundle.input_enc.as_deref())
            .bind(bundle.key_id)
            .bind(workflow_execution_id)
            .bind(trigger_type)
            .execute(&self.pool)
            .await
        } else {
            // allow-trigger-type-column: same as the race-safe arm above —
            // module_executions.trigger_type is a real column.
            sqlx::query(
                "INSERT INTO module_executions \
                 (id, module_id, user_id, status, \
                  input_data, input_data_enc, payload_enc_key_id, \
                  workflow_execution_id, trigger_type, started_at) \
                 VALUES ($1, $2, $3, 'running', $4, $5, $6, $7, $8, NOW()) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(id)
            .bind(module_id)
            .bind(user_id)
            .bind(pt_input)
            .bind(bundle.input_enc.as_deref())
            .bind(bundle.key_id)
            .bind(workflow_execution_id)
            .bind(trigger_type)
            .execute(&self.pool)
            .await
        };
        result.map(|_| ()).map_err(|e| -> BoxError { e.into() })
    }

    async fn record_completed(
        &self,
        id: Uuid,
        status: &str,
        output: &JsonValue,
        duration_ms: i32,
        error_message: Option<&str>,
    ) -> Result<(), BoxError> {
        // Phase A encryption: encrypt output payload at rest. The COALESCE
        // on payload_enc_key_id preserves the key set during record_started
        // (same DEK across the row) and only sets it on first write if
        // record_started ran without encryption (legacy migration window).
        let bundle = talos_module_payload_encryption::encrypt_payload_bundle(
            self.secrets_manager.as_ref(),
            None,
            Some(output),
            None,
        )
        .await
        .map_err(|e| -> BoxError { e.into() })?;
        // MCP-987 (2026-05-15): DLP-redact the plaintext-fallback path
        // on `output_data`. Same rationale as record_started above —
        // module outputs (LLM responses, HTTP bodies, downstream JSON)
        // routinely carry secret-shaped values when modules echo their
        // own headers or pass-through tokens. Defense-in-depth for the
        // failure-mode of `encrypt_payload_bundle`.
        let encrypting = bundle.encrypting();
        let redacted_pt_output = if encrypting {
            None
        } else {
            Some(talos_dlp_provider::redact_json(output))
        };
        let pt_output = redacted_pt_output.as_ref();
        // MCP-968 (2026-05-15): DLP-redact error_message at the bind
        // boundary. Pre-fix `error_message: Option<&str>` (raw module
        // failure text — host-fn errors, panic messages, upstream API
        // responses) was bound directly into `module_executions.error_message`
        // without scrubbing. Same sibling class as MCP-967 on the
        // workflow_executions side: output_data was already covered
        // by the encrypt_payload_bundle above, error_message was the
        // parallel gap. `redact_str` is infallible.
        //
        // MCP-1166 (2026-05-17): truncate-then-redact discipline.
        // Sibling sweep of MCP-1161/1164/1165 — `module_executions.error_message`
        // is the parallel column to `workflow_executions.error_message`
        // (the latter has now-truncated writers across WorkflowRepository,
        // AdvancedRepository, ActorRepository). Module errors include
        // host-fn errors, panic messages, upstream API response bodies —
        // potentially multi-MB. 4 KiB matches the MCP-1161/1164
        // ceiling on the parallel workflow_executions column.
        let redacted_error = error_message.map(|e| {
            let truncated: &str = if e.len() > 4096 {
                talos_text_util::truncate_at_char_boundary(e, 4096)
            } else {
                e
            };
            talos_dlp_provider::redact_str(truncated)
        });

        sqlx::query(
            "UPDATE module_executions \
             SET status = $1, output_data = $2, output_data_enc = $3, \
                 payload_enc_key_id = COALESCE(payload_enc_key_id, $4), \
                 duration_ms = $5, error_message = $6, completed_at = NOW() \
             WHERE id = $7",
        )
        .bind(status)
        .bind(pt_output)
        .bind(bundle.output_enc.as_deref())
        .bind(bundle.key_id)
        .bind(duration_ms)
        .bind(redacted_error.as_deref())
        .bind(id)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| -> BoxError { e.into() })
    }

    async fn resolve_module_id(&self, id_or_template: Uuid) -> Uuid {
        // Phase 5.1: post-legacy-table drop, the `module_executions.module_id`
        // FK targets `modules.id` directly. This resolver is now an identity
        // function — the trait method is required by
        // `talos_workflow_engine_core::ModuleExecutionStore`, so we keep
        // the impl but skip the DB round-trip.
        id_or_template
    }
}
