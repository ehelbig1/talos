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

    /// The real `record_started` body. Split out of the trait method purely so
    /// the failure counter below has ONE exit point covering BOTH failure edges
    /// (payload-encryption/DEK resolution, and the INSERT itself) instead of a
    /// count bolted onto each `?`.
    ///
    /// This is the only non-test `ModuleExecutionStore` impl in the workspace,
    /// and all three engine callers of `record_started` route through it — so
    /// instrumenting here covers every production start-row write without
    /// touching `talos-workflow-engine` (which owns the trait, not the DB).
    async fn record_started_inner(&self, ctx: ExecutionStartedContext<'_>) -> Result<(), BoxError> {
        let ExecutionStartedContext {
            id,
            module_id,
            user_id,
            workflow_execution_id,
            input,
            trigger_type,
            race_safe_status,
            actor_id,
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
        // MCP-S2: AAD = module_execution_id binds the ciphertext to
        // this row so an attacker with DB write capability can't swap
        // payload columns across executions.
        // DLP-redact BEFORE encryption so the AT-REST ciphertext is scrubbed too
        // — not just the plaintext fallback below. A decrypted trace read
        // (`get_node_io`) must not surface secret-shaped values that leaked into
        // a node input (e.g. a token in injected actor memory). Parity with the
        // output path (`collect_success_output`) and the sibling controller-side
        // store (`talos-module-executions`). Redaction only rewrites the STORED
        // copy — the module receives its runtime input over NATS, untouched.
        let redacted_input = talos_dlp_provider::redact_json(input);
        let bundle = talos_module_payload_encryption::encrypt_payload_bundle(
            self.secrets_manager.as_ref(),
            id,
            // Per-org DEK arc: scope to the execution's tenant org via the parent
            // workflow execution (resolved inside encrypt_payload_bundle).
            Some(workflow_execution_id),
            Some(&redacted_input),
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
        // Reuse the already-redacted input for the plaintext-fallback column.
        let redacted_pt_input = if encrypting {
            None
        } else {
            Some(redacted_input)
        };
        let pt_input = redacted_pt_input.as_ref();

        // MCP-S2: persist the AAD format version alongside the bundle.
        let payload_format = bundle.format_version;
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
                  input_data, input_data_enc, payload_enc_key_id, payload_format, \
                  workflow_execution_id, trigger_type, actor_id, started_at) \
                 SELECT $1, $2, $3, \
                     CASE WHEN EXISTS( \
                         SELECT 1 FROM workflow_executions \
                         WHERE id = $8 AND status IN ('failed', 'cancelled') \
                     ) THEN 'cancelled' ELSE 'running' END, \
                     $4, $5, $6, $7, $8, $9, $10, NOW() \
                 ON CONFLICT DO NOTHING",
            )
            .bind(id)
            .bind(module_id)
            .bind(user_id)
            .bind(pt_input)
            .bind(bundle.input_enc.as_deref())
            .bind(bundle.key_id)
            .bind(payload_format)
            .bind(workflow_execution_id)
            .bind(trigger_type)
            .bind(actor_id)
            .execute(&self.pool)
            .await
        } else {
            // allow-trigger-type-column: same as the race-safe arm above —
            // module_executions.trigger_type is a real column.
            sqlx::query(
                "INSERT INTO module_executions \
                 (id, module_id, user_id, status, \
                  input_data, input_data_enc, payload_enc_key_id, payload_format, \
                  workflow_execution_id, trigger_type, actor_id, started_at) \
                 VALUES ($1, $2, $3, 'running', $4, $5, $6, $7, $8, $9, $10, NOW()) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(id)
            .bind(module_id)
            .bind(user_id)
            .bind(pt_input)
            .bind(bundle.input_enc.as_deref())
            .bind(bundle.key_id)
            .bind(payload_format)
            .bind(workflow_execution_id)
            .bind(trigger_type)
            .bind(actor_id)
            .execute(&self.pool)
            .await
        };
        result.map(|_| ()).map_err(|e| -> BoxError { e.into() })
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
        let result = self.record_started_inner(ctx).await;
        // The SINGLE production chokepoint for `module_executions` start-row
        // writes. `record_started`'s Err is NON-FATAL at every caller by design
        // (the engine logs it and dispatches anyway), which is precisely why it
        // needs a metric: the execution still runs, but its row never exists, so
        // its WASM logs orphan (`talos_wasm_log_orphaned_total{kind=
        // "no_execution_row"}`) and get_execution_logs / get_node_io / cost
        // attribution quietly under-report. Before this counter the only trace
        // was a `tracing::error!` at each caller.
        //
        // Unlabelled on purpose: the failure edges are "DEK/encryption" and
        // "INSERT", and neither an execution id, a module id, a user id nor the
        // sqlx error text may become a label. The error itself keeps carrying
        // that detail to the caller's log.
        //
        // Deliberately NOT routed through a shared warn-and-count helper — see
        // the detector-metrics block in `talos_metrics::TalosMetrics` for why
        // one would re-blind structural check 58.
        if result.is_err() {
            if let Some(m) = talos_metrics::global() {
                m.module_execution_record_started_failures_total.inc();
            }
        }
        result
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
        //
        // MCP-S2: AAD = the same module_execution_id used in
        // record_started, so the v1 ciphertext stays decryptable.
        let bundle = talos_module_payload_encryption::encrypt_payload_bundle(
            self.secrets_manager.as_ref(),
            id,
            // record_completed: workflow_execution_id isn't in scope; pass None so
            // encrypt_payload_bundle resolves the SAME org from the existing row
            // (keeps the shared payload_enc_key_id consistent with record_started).
            None,
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

        // MCP-S2: persist payload_format alongside the ciphertext so
        // the read dispatcher routes v1 rows through the AAD path.
        // BUT only update the column when this UPDATE writes a new
        // ciphertext — the empty-bundle short-circuit in
        // `encrypt_payload_bundle` returns format_version=0 which
        // would otherwise overwrite a row's v1 stamp from
        // record_started (sibling of the module-executions fix in
        // talos-module-executions::complete_execution).
        let format_arg: Option<i16> = if bundle.encrypting() {
            Some(bundle.format_version)
        } else {
            None
        };
        // `module_executions.fuel_consumed` was a DEAD COLUMN until 2026-08:
        // 0 of 25,213 rows populated. Its only writer
        // (`ModuleExecutionService::complete_execution`) is reachable solely
        // through `complete_execution_best_effort`, which has no callers
        // workspace-wide, so the column — and the `fuelConsumed` field the
        // GraphQL `ModuleExecution` type exposes from it — always read NULL.
        // A column that always reads NULL is worse than an absent one: the
        // next person doing fuel archaeology reads "no fuel was used" instead
        // of "nobody ever wrote this".
        //
        // `record_completed` is the live terminal writer on the engine path,
        // and the worker already stamps `__fuel_consumed__` into the node
        // output — the same key `ControllerNodeHook::on_node_completed` reads
        // for `execution_cost_rollup`. Reading it here costs one JSON lookup
        // and makes the two ledgers agree by construction.
        //
        // Scope of what this does and does NOT fix, stated rather than
        // implied: `execution_cost_rollup` remains the authoritative per-node
        // fuel record and is the only one with the `max_fuel` ceiling
        // alongside. This write makes the standalone-module row honest (those
        // never get a rollup row at all — rollups are keyed by workflow node)
        // and stops the GraphQL field lying. It does NOT retro-fill the 25,213
        // historical rows, which stay NULL.
        //
        // Absent key ⇒ NULL, not 0: a pre-stamp worker, a system node, or a
        // failure path that never ran the module has no measurement, and
        // writing 0 would assert one. Same reason the message rewrite above
        // refuses to print the limit where a measurement belongs.
        let fuel_consumed: Option<i64> = output
            .get(talos_workflow_engine_core::reserved_keys::FUEL_CONSUMED)
            .and_then(JsonValue::as_i64)
            .filter(|f| *f > 0);

        // Status guard — FIRST terminal writer wins.
        //
        // Byte-for-byte the same predicate
        // `ModuleExecutionService::complete_execution_from_worker` has always
        // carried; this impl was the sibling that never grew it. The guard
        // earns its place on TWO writers that genuinely race this one, plus a
        // third that is currently excluded for a reason worth writing down
        // correctly:
        //
        //  1. THE STUCK-EXECUTION SWEEP — a real, unavoidable writer of the
        //     same row, and the reason this guard is not merely defensive. It
        //     converts any row still `'running'` after 30 minutes to
        //     `'timeout'` / `error_type='stuck'`. It races nothing and asks
        //     nobody: a node that legitimately runs longer than the threshold
        //     (or whose finalize is delayed behind a DB hiccup) is swept, and
        //     then this UPDATE would arrive and re-clobber it to `'completed'`
        //     — erasing the record that the platform had already given up on
        //     that worker. First-writer-wins is the right resolution because
        //     the sweep's write is a STATEMENT ABOUT THE LEDGER ("no
        //     completion was recorded in 30 minutes") that a later arrival
        //     does not retroactively falsify.
        //
        //  2. THE SIBLING-CANCEL WRITER (`talos-engine`'s node hook, on
        //     workflow failure: `UPDATE … SET status='cancelled' WHERE
        //     workflow_execution_id = $1 AND status='running'`). Without the
        //     guard a node whose result lands after its parent workflow failed
        //     resurrects a `'cancelled'` row as `'completed'` — the very
        //     phantom `race_safe_status` exists to prevent, undone one
        //     statement later. This is not hypothetical: it is the largest
        //     non-sweep terminal population in the live table.
        //
        //  3. `complete_execution_from_worker`, hanging off the global
        //     audit-topic result subscriber. It does NOT reach these rows
        //     today — but NOT for the reason an earlier draft of this comment
        //     gave, and the wrong reason is worth naming so it is not
        //     re-derived. That draft said the trait default of
        //     `JobTransport::new_reply_inbox` is `None` and `None` routes
        //     results to the audit topic. It does not. When
        //     `new_reply_inbox()` returns `None`, `send_with_optional_inbox`
        //     falls back to `transport.request(topic, payload)`; core NATS
        //     allocates its OWN reply inbox and puts it on the wire, so the
        //     worker's `pick_trusted_reply_topic` takes the
        //     `(signed: None, wire: Some(inbox))` arm and publishes THERE.
        //     Only `(None, None)` reaches the audit topic, and that needs a
        //     transport whose `request` carries no reply subject at all — in
        //     which case `request()` never returns, the dispatcher times out,
        //     and THIS finalize writes `'timeout'` first anyway. So the
        //     exclusion is structural rather than an override a future
        //     transport might forget: there is no transport shape that both
        //     routes to the audit subscriber AND lets the engine's dispatch
        //     return before it.
        //
        // The guard's value therefore rests on (1) and (2), which are live,
        // not on (3). Keeping it costs one predicate and makes
        // first-writer-wins a property of the statement instead of an
        // invariant maintained by argument.
        //
        // Also note this predicate makes the UPDATE idempotent, which is what
        // lets every caller treat finalize as best-effort and retry-free.
        //
        // A no-op UPDATE is NOT an error here: `record_completed`'s callers
        // are all best-effort, and "someone else already closed this row" is
        // a correct outcome, not a failure to report.
        //
        // BUT IT MUST NOT BE INVISIBLE. Discarding `rows_affected()` means a
        // future regression in which the guard ALWAYS refuses this write —
        // a sweep threshold dropped to zero, a status literal renamed, a
        // second writer that now always wins the race — would look exactly
        // like success at the only place that can see it, and would present
        // downstream as the same silent symptom this whole change exists to
        // stop: an empty `WHERE status='completed'` population. Note the
        // asymmetry that made that plausible: `record_started` has a failure
        // counter (`talos_module_execution_record_started_failures_total`) and
        // `record_completed` had no counterpart of any kind.
        //
        // `debug!`, deliberately, not `warn!`: a refusal is a LEGITIMATE and
        // expected outcome (the sweep or the sibling-cancel writer got here
        // first), so warning on it would train operators to ignore it. What is
        // wanted is a line that exists to be grepped when the population goes
        // empty — cheap, silent by default, and enough to distinguish "the
        // engine never called finalize" from "the engine called it and the
        // guard refused". Distinguishing those two took a full DB census the
        // first time.
        let refused = sqlx::query(
            "UPDATE module_executions \
             SET status = $1, output_data = $2, output_data_enc = $3, \
                 payload_enc_key_id = COALESCE(payload_enc_key_id, $4), \
                 payload_format = COALESCE($5, payload_format), \
                 duration_ms = $6, error_message = $7, \
                 fuel_consumed = COALESCE($8, fuel_consumed), completed_at = NOW() \
             WHERE id = $9 AND status IN ('pending', 'running')",
        )
        .bind(status)
        .bind(pt_output)
        .bind(bundle.output_enc.as_deref())
        .bind(bundle.key_id)
        .bind(format_arg)
        .bind(duration_ms)
        .bind(redacted_error.as_deref())
        .bind(fuel_consumed)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| -> BoxError { e.into() })?
        .rows_affected()
            == 0;
        if refused {
            tracing::debug!(
                module_execution_id = %id,
                status,
                "record_completed matched no row — already terminal (swept, \
                 sibling-cancelled, or finalized by another writer), or the id \
                 names no row. Expected in isolation; a SUSTAINED run of these \
                 means the ledger's 'completed' population is being written by \
                 nobody."
            );
        }
        Ok(())
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

/// D2 pin for `talos_module_execution_record_started_failures_total`.
///
/// Drives the REAL production `record_started` (the trait method the engine
/// calls) into its real INSERT failure edge and asserts the counter moved —
/// deliberately NOT a `render_prometheus` shape test. A metrics-render test is
/// exactly what let `talos_dek_cache_size` and
/// `talos_module_payload_encryption_failures_total` read as instrumented for
/// months while every production path was silent (#620).
#[cfg(test)]
mod record_started_metric_tests {
    use super::PostgresModuleExecutionStore;
    use serde_json::json;
    use talos_workflow_engine_core::{ExecutionStartedContext, ModuleExecutionStore};
    use uuid::Uuid;

    /// `set_global` is a process-wide one-shot `OnceLock` and sibling tests in
    /// this binary share the registry, so read DELTAS through
    /// `talos_metrics::global()` rather than absolutes off a local `Arc`.
    #[tokio::test]
    async fn record_started_failure_is_counted_on_the_production_path() {
        talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
        let m = talos_metrics::global().expect("global installed");
        let read = || m.module_execution_record_started_failures_total.get();

        // A pool that can never connect: the INSERT fails at acquire time.
        // Short acquire timeout so the failure lands in ~250ms rather than on
        // sqlx's 30s default.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(250))
            .connect_lazy("postgres://127.0.0.1:1/talos_never_connects")
            .expect("lazy pool build");
        // No SecretsManager wired → `encrypt_payload_bundle` returns an empty
        // bundle without erroring, so the ONLY failure edge exercised here is
        // the INSERT itself.
        let store = PostgresModuleExecutionStore::new(pool);

        let input = json!({"k": "v"});
        for race_safe_status in [true, false] {
            let before = read();
            store
                .record_started(ExecutionStartedContext {
                    id: Uuid::new_v4(),
                    module_id: Uuid::new_v4(),
                    user_id: Uuid::new_v4(),
                    workflow_execution_id: Uuid::new_v4(),
                    input: &input,
                    trigger_type: "manual",
                    race_safe_status,
                    actor_id: None,
                })
                .await
                .expect_err("INSERT against a dead pool must fail");
            assert_eq!(
                read() - before,
                1.0,
                "record_started failure (race_safe_status={race_safe_status}) must reach \
                 talos_module_execution_record_started_failures_total"
            );
        }
    }
}
