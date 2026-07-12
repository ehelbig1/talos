//! Controller-side implementation of [`NodeLifecycleHook`].
//!
//! Handles every cross-cutting concern the Talos controller owns at
//! per-node granularity:
//!
//! 1. **Fuel cost attribution** (on_node_completed). When a node's
//!    output contains `__fuel_consumed__: i64 > 0`, the amount is
//!    written to `execution_cost_rollup`. Fire-and-forget —
//!    [`talos_cost_attribution::record_fuel`] spawns the INSERT.
//! 2. **`__memory_write__` protocol** (on_node_completed +
//!    on_pipeline_step_completed). When the execution is owned by an
//!    actor and the node output contains a `__memory_write__` JSON
//!    object, the payload is persisted to `actor_memory` via
//!    [`talos_actor_memory_service::persist_memory_with_metadata`].
//!    This is a controller-internal protocol that lets any node return
//!    `{ "__memory_write__": { "key": ..., "value": ..., metadata: {...}, ... } }`
//!    to trigger an actor-memory write without a dedicated host function.
//!    When `metadata` (a JSON object) is present, it is stored in the
//!    dedicated `actor_memory.metadata` JSONB column — enabling the
//!    `search_filtered(exclude_kinds: [...])` self-reference-loop guard
//!    without requiring the agent-node capability world.
//!    Fires at both node-completion and per-pipeline-step so chain-
//!    dispatched modules can emit memory writes too.
//! 3. **Dead-letter-queue + sibling cancellation** (on_node_failed).
//!    Terminal node failure enqueues the error + payload into
//!    `dead_letter_queue` and cancels any still-running sibling
//!    `module_executions` rows so they don't linger past workflow
//!    abort. Both are SQL writes — spawned so they don't delay the
//!    abort path.

use serde_json::Value as JsonValue;
use sqlx::{Pool, Postgres};
use talos_workflow_engine_core::{NodeCompletionContext, NodeLifecycleHook};
use uuid::Uuid;

/// Substrings used to classify `__memory_write__` failures into one
/// of three metric label buckets: `crypto`, `db`, or `other`.
///
/// **The wording match is fragile.** The underlying error returns
/// `anyhow::Error` from `talos_actor_memory_service` which wraps
/// errors from `talos_secrets_manager` (encrypt/decrypt), `sqlx`
/// (database I/O), and assorted ad-hoc strings. Until those grow a
/// typed-error API, classification depends on a substring of the
/// stringified error matching one of the markers below.
///
/// Markers are split into named constants here so the contract is
/// visible to a future reader who refactors the upstream errors —
/// a search for `MEMORY_WRITE_*_MARKERS` will surface every
/// downstream classifier that depends on the wording.
const MEMORY_WRITE_CRYPTO_MARKERS: &[&str] = &["decrypt_dek", "encrypt_value", "aead::Error"];
const MEMORY_WRITE_DB_MARKERS: &[&str] = &["database", "pool", "sqlx"];

/// Classify a stringified `__memory_write__` failure for metric
/// labelling. Pure function — exposed via `pub(crate)` purely so
/// `node_hook_tests::classify_*` can pin the substring contract.
///
/// Resolution order: crypto markers win over DB markers (a crypto
/// error happening in a DB-bound code path should still page the
/// crypto on-call, not the DB on-call). Anything that matches
/// neither bucket is `"other"`.
pub(crate) fn classify_memory_write_failure(err_str: &str) -> &'static str {
    if MEMORY_WRITE_CRYPTO_MARKERS
        .iter()
        .any(|m| err_str.contains(m))
    {
        "crypto"
    } else if MEMORY_WRITE_DB_MARKERS.iter().any(|m| err_str.contains(m)) {
        "db"
    } else {
        "other"
    }
}

/// Default Talos impl of [`NodeLifecycleHook`]. Owns a `PgPool` so it
/// can persist fuel rollups and actor-memory writes synchronously
/// spawned on the Tokio runtime.
pub struct ControllerNodeHook {
    pool: Pool<Postgres>,
}

impl ControllerNodeHook {
    /// Build a hook bound to `pool`.
    #[must_use]
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

impl std::fmt::Debug for ControllerNodeHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControllerNodeHook")
            .field("pool", &self.pool)
            .finish()
    }
}

impl ControllerNodeHook {
    /// Shared `__memory_write__` extractor. Returns early when either
    /// the execution has no actor (nothing to attribute the write to)
    /// or the output lacks a well-formed `__memory_write__` payload.
    /// Spawns the `actor_memory` INSERT so a slow DB never stalls
    /// dispatch.
    ///
    /// Visibility for the actor-unbound case (added 2026-04-29): when a
    /// node DOES emit a well-formed `__memory_write__` envelope but no
    /// actor is bound to the execution, the write is silently dropped
    /// — there is no actor to attribute it to. Pre-fix this was an
    /// invisible no-op: operators saw their `MEMORY_WRITE_KEY`-configured
    /// nodes complete cleanly with no resulting actor_memory row and no
    /// log entry to explain why. The most common cause is calling
    /// `trigger_workflow` without `actor_id` on a workflow whose
    /// `workflows.actor_id` column is also NULL — the engine builder's
    /// `with_effective_actor(arg, workflow_default)` resolves to None and
    /// the hook bails. We now emit one WARN per dropped envelope with the
    /// key + node id so the gap is greppable.
    /// `pub` (2026-07-07): `test_module` reuses this exact path so a
    /// module's `__memory_write__` behaves identically in the dev-test
    /// surface and in live workflows — pre-fix, test_module accepted the
    /// envelope and silently dropped it (the hook only fired on engine
    /// executions), a confusing divergence found by the functional sweep.
    pub fn persist_memory_write_if_present(&self, actor_id: Option<Uuid>, output: &JsonValue) {
        let Some(mw) = output
            .get("__memory_write__")
            .and_then(JsonValue::as_object)
        else {
            return;
        };
        let Some(actor_id) = actor_id else {
            // Surface the silent-drop. Bound key length to prevent log
            // amplification from pathological MEMORY_WRITE_KEY values.
            //
            // MCP-990 (2026-05-15): DLP-redact the key preview FIRST.
            // `mw.get("key")` is WASM-supplied (the module's
            // `__memory_write__` envelope) — a malicious module could
            // deliberately emit a secret-prefixed key, route the
            // payload to a node missing the actor binding, and
            // exfiltrate via this operator-log preview. Sibling fix
            // shape to the validator-rejection branch below.
            let key_raw = mw
                .get("key")
                .and_then(JsonValue::as_str)
                .unwrap_or("<missing>");
            let key_preview: String = talos_dlp_provider::redact_str(key_raw)
                .chars()
                .take(120)
                .collect();
            tracing::warn!(
                key = %key_preview,
                "__memory_write__ envelope emitted by node but no actor is bound \
                 to this execution — write dropped. Pass actor_id to trigger_workflow, \
                 or set workflows.actor_id on the workflow definition."
            );
            return;
        };
        // MCP-835 (2026-05-14): route through canonical
        // `talos_memory::validate_memory_key` (MCP-834). The pre-fix
        // `is_empty()` check let WASM-guest envelopes through with
        //   * whitespace-only keys (`"   "` — MCP-388 lookup-miss
        //     class: persists a key no `actor_recall` can match because
        //     downstream readers all trim now);
        //   * control chars / `\0` (MCP-431 — corrupt downstream
        //     UPDATE-by-key with opaque Postgres errors);
        //   * over-500-char keys (caught at the service boundary but
        //     surfaces as a generic DB error in metrics, indistinguishable
        //     from a real outage).
        // Engine-side validation IS the right place — the WASM guest is
        // potentially untrusted source code. Bypass via the service layer
        // would only catch length, and the trim invariant would never
        // be enforced (the service preserves the caller's key by design,
        // mirroring MCP-388). Failure here is best-effort like every
        // other __memory_write__ failure: log + metric, don't stall
        // the execution.
        let key_raw = mw.get("key").and_then(JsonValue::as_str).unwrap_or("");
        let key = match talos_memory::validate_memory_key(key_raw) {
            Ok(trimmed) => trimmed.to_string(),
            Err(reason) => {
                // MCP-990 (2026-05-15): DLP-redact the rejected key
                // preview. `key_raw` originates from the WASM module's
                // `__memory_write__` envelope — a malicious module
                // could deliberately submit a too-long key (>500 chars,
                // triggering validation failure) prefixed with a
                // secret-shaped value (`sk-ant-...`, `Bearer xyz`) to
                // exfiltrate via the operator-log preview that fires
                // exclusively on validation failure. Sibling class to
                // MCP-989 — WASM-supplied content reaching operator log
                // surfaces must pass through `redact_str` first. The
                // 120-char bound is preserved for log amplification
                // protection; redaction runs idempotently before the
                // truncate so secret prefixes never see the truncate
                // call.
                let key_preview: String = talos_dlp_provider::redact_str(key_raw)
                    .chars()
                    .take(120)
                    .collect();
                tracing::warn!(
                    target: "talos_audit",
                    key = %key_preview,
                    reason,
                    "__memory_write__ envelope key rejected by validator — write dropped"
                );
                if let Some(m) = talos_metrics::global() {
                    m.memory_write_failures_total
                        .with_label_values(&["invalid_key"])
                        .inc();
                }
                return;
            }
        };
        let value = mw.get("value").cloned().unwrap_or(JsonValue::Null);
        let memory_type = mw
            .get("memory_type")
            .and_then(JsonValue::as_str)
            .unwrap_or("episodic")
            .to_string();
        let ttl_hours = mw
            .get("ttl_hours")
            .and_then(JsonValue::as_f64)
            .unwrap_or(168.0);
        // Metadata is optional. When present and an object, it is stored in the
        // dedicated actor_memory.metadata JSONB column (not merged into value).
        // Non-object metadata is ignored — the DB column is typed JSONB object.
        let metadata = mw.get("metadata").filter(|v| v.is_object()).cloned();

        let pool = self.pool.clone();
        tokio::spawn(async move {
            if let Err(e) = talos_actor_memory_service::persist_memory_with_metadata(
                &pool,
                actor_id,
                &key,
                &value,
                metadata.as_ref(),
                &memory_type,
                Some(ttl_hours),
            )
            .await
            {
                // Classify for metric label. Crypto / DB errors are the
                // high-blast-radius failures the alerts page on. Marker
                // set lives in MEMORY_WRITE_*_MARKERS at the top of this
                // file so the substring contract is visible + testable.
                let reason = classify_memory_write_failure(&e.to_string());
                if let Some(m) = talos_metrics::global() {
                    m.memory_write_failures_total
                        .with_label_values(&[reason])
                        .inc();
                }
                tracing::warn!(
                    %actor_id,
                    %key,
                    error = %e,
                    reason,
                    "__memory_write__ persist failed",
                );
            }
        });
    }
}

impl NodeLifecycleHook for ControllerNodeHook {
    fn on_node_completed(&self, ctx: NodeCompletionContext<'_>, output: &JsonValue) {
        // ── 1. Cost attribution: per-node fuel consumption ────────────
        let fuel = output
            .get("__fuel_consumed__")
            .and_then(JsonValue::as_i64)
            .unwrap_or(0);
        if fuel > 0 {
            let label = ctx
                .node_label
                .map(str::to_string)
                .unwrap_or_else(|| ctx.node_id.to_string());
            // `__fuel_limit__` is the limit the WORKER actually enforced
            // (config override > module default, engine-clamped) — stamped
            // next to `__fuel_consumed__`. None for outputs from pre-stamp
            // workers; readers COALESCE back to modules.max_fuel.
            let max_fuel = output.get("__fuel_limit__").and_then(JsonValue::as_i64);
            talos_cost_attribution::record_fuel(
                self.pool.clone(),
                ctx.actor_id,
                ctx.workflow_id,
                ctx.execution_id,
                label,
                ctx.module_id,
                fuel,
                i64::try_from(ctx.wall_time_ms).unwrap_or(i64::MAX),
                max_fuel,
            );
        }

        // ── 2. `__memory_write__` protocol: persist to actor_memory ──
        self.persist_memory_write_if_present(ctx.actor_id, output);

        // ── 3. `__ml_distill__` protocol (RFC 0011 P2d): LLM answers →
        // dataset auto-append + shadow prediction. Same opt-in-output
        // shape and actor-binding contract as `__memory_write__`; the
        // whole flow is tokio::spawn'd inside, so node-completion
        // latency is unchanged.
        talos_ml::spawn_distill_from_output(ctx.actor_id, output);
    }

    fn on_pipeline_step_completed(&self, actor_id: Option<Uuid>, step_output: &JsonValue) {
        // Pipeline-step memory writes: same extraction, NO fuel
        // attribution. Chain-level fuel is recorded once on the chain
        // head via on_node_completed; double-billing per step would
        // inflate rollups by the chain length.
        self.persist_memory_write_if_present(actor_id, step_output);
        talos_ml::spawn_distill_from_output(actor_id, step_output);
    }

    fn on_node_failed(
        &self,
        ctx: NodeCompletionContext<'_>,
        error_message: &str,
        payload: Option<&JsonValue>,
    ) {
        // DLQ + sibling cancellation — both SQL writes, both spawned
        // so they never delay the workflow-abort return path. The
        // engine has already flipped `executing` into drop state
        // before calling this; any in-flight sibling futures are
        // being cancelled by the abort anyway. The explicit SQL
        // cancellation below is defense-in-depth for cases where a
        // worker has persisted its `module_executions` row and no
        // future on the engine side still holds it.
        //
        // MCP-466: DLP-scrub both `error_message` and `payload` before
        // they land in `dead_letter_queue`. Upstream code paths that
        // construct the engine error (sibling repo `talos-workflow-
        // engine`) have no DLP dep and frequently embed worker-side
        // panic strings, upstream HTTP error bodies, or OAuth-reply
        // fragments verbatim — patterns that match `sk-*`, `ghp_*`,
        // Bearer tokens, etc. DLQ rows are readable via MCP/GraphQL
        // (`list_alerts`, dlq subscription) and breach the "never
        // store secrets unencrypted" invariant when unscrubbed.
        // Scrubbing happens AFTER the move into the spawned task so
        // we don't pay for redaction in the dispatch hot path — the
        // abort return is unblocked first.
        //
        // MCP-1198 (2026-05-17): apply truncate-first on error_message
        // and measure-first on payload — DLQ rows have NO TTL by
        // default and surface in operator dashboards / DLQ
        // subscription, so unbounded unredacted content amplifies
        // storage costs forever. error_message is engine-side
        // `e.to_string()` (wasmtime traces, NATS-relayed HTTP error
        // bodies) — 4 KiB ceiling matches MCP-1161/1164/1167 canonical
        // for the parallel `workflow_executions.error_message`
        // column. payload is the FAILING node's input/output JSON
        // (LLM responses, HTTP bodies, arbitrary upstream data) —
        // 1 MiB cap via `redact_json_bounded` matches MCP-1195/1197
        // canonical for JSONB log/audit columns; over-cap drops to
        // NULL with structured WARN, error_message + node_id still
        // persist so the operator retains the failure record.
        let pool = self.pool.clone();
        let workflow_id = ctx.workflow_id;
        let execution_id = ctx.execution_id;
        let node_id = ctx.node_id;
        let error_owned = error_message.to_string();
        let payload_owned = payload.cloned();
        tokio::spawn(async move {
            let truncated_error: &str = if error_owned.len() > 4096 {
                talos_text_util::truncate_at_char_boundary(&error_owned, 4096)
            } else {
                &error_owned
            };
            let scrubbed_error = talos_dlp_provider::redact_str(truncated_error);
            let scrubbed_payload = payload_owned
                .as_ref()
                .and_then(talos_dlp_provider::redact_json_bounded);
            if let Err(e) = sqlx::query(
                "INSERT INTO dead_letter_queue \
                 (workflow_id, execution_id, node_id, error_message, payload) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(workflow_id)
            .bind(execution_id)
            .bind(node_id)
            .bind(&scrubbed_error)
            .bind(&scrubbed_payload)
            .execute(&pool)
            .await
            {
                tracing::warn!(
                    %execution_id,
                    %node_id,
                    error = %e,
                    "Failed to enqueue DLQ row",
                );
            }
            if let Err(e) = sqlx::query(
                "UPDATE module_executions \
                 SET status = 'cancelled', completed_at = NOW(), \
                     error_message = 'Workflow failed — parallel sibling cancelled' \
                 WHERE workflow_execution_id = $1 AND status = 'running'",
            )
            .bind(execution_id)
            .execute(&pool)
            .await
            {
                tracing::warn!(
                    %execution_id,
                    error = %e,
                    "Failed to cancel running sibling module_executions",
                );
            }
        });
    }
}

#[cfg(test)]
mod classify_tests {
    use super::*;

    /// Pin the substring contract for memory-write failure
    /// classification. Marker drift is an alerts-go-quiet bug class:
    /// if the upstream error wording changes and these tests still
    /// pass, classification still works. If they fail, the
    /// classifier needs to be updated alongside the upstream change.
    #[test]
    fn classify_crypto_errors() {
        assert_eq!(
            classify_memory_write_failure("decrypt_dek failed: invalid wrap"),
            "crypto"
        );
        assert_eq!(
            classify_memory_write_failure("encrypt_value: aead::Error: tag mismatch"),
            "crypto"
        );
        assert_eq!(
            classify_memory_write_failure("aead::Error - generic GCM failure"),
            "crypto"
        );
    }

    #[test]
    fn classify_db_errors() {
        assert_eq!(
            classify_memory_write_failure("database connection lost"),
            "db"
        );
        assert_eq!(
            classify_memory_write_failure("pool exhausted: timeout 5s"),
            "db"
        );
        assert_eq!(
            classify_memory_write_failure("sqlx::Error::Io: broken pipe"),
            "db"
        );
    }

    #[test]
    fn classify_unknown_errors() {
        assert_eq!(
            classify_memory_write_failure("memory_type 'epsiodic' is not a known kind"),
            "other"
        );
        assert_eq!(classify_memory_write_failure(""), "other");
        assert_eq!(
            classify_memory_write_failure("graph extraction failed"),
            "other"
        );
    }

    #[test]
    fn crypto_takes_precedence_over_db() {
        // A crypto error inside a DB-touching operation gets classified
        // as crypto so the crypto on-call sees the page, not DB.
        // (Realistic case: AES decrypt failing while reading a row.)
        assert_eq!(
            classify_memory_write_failure(
                "sqlx query succeeded but aead::Error during decrypt_dek"
            ),
            "crypto"
        );
    }
}
