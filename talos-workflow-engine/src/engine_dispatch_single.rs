//! Single-node dispatch — extracted from engine.rs.
//!
//! Hosts `run_single_node_dispatch`, the per-node branch of the
//! reactor that handles plain module dispatches (everything that
//! isn't a system-kind handler or a chain head). Pure code movement
//! from the previous engine.rs location — no behaviour change.
//! Lifted out so the dispatch path stays auditable in isolation
//! alongside `engine_dispatch_pipeline`.

use std::sync::Arc;

use petgraph::graph::NodeIndex;
use serde_json::Value as JsonValue;
use talos_workflow_engine_core::{DispatchJob, ExecutionStartedContext, NodeEventWrite};
use uuid::Uuid;

use crate::emit_event_spawn;
use crate::engine::{ParallelWorkflowEngine, DEFAULT_NODE_TIMEOUT_SECS};
use crate::secrets_pipeline::extract_vault_paths;

impl ParallelWorkflowEngine {
    /// Build and await the full single-node dispatch future.
    ///
    /// Runs the approval gate, merges module + node configs, emits an
    /// input-preview event, records the `module_executions` start row,
    /// resolves encrypted secrets, assembles a [`DispatchJob`], and
    /// hands it to the [`NodeDispatcher`]. Returns the scheduler's
    /// `(NodeIndex, Result<JsonValue, String>)` completion tuple.
    ///
    /// Extracted from the reactor loop so the scheduler body reads as
    /// a sequence of handler dispatches rather than a 370-line inline
    /// closure. Semantics are preserved verbatim.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run_single_node_dispatch(
        &self,
        node_idx: NodeIndex,
        node_id: Uuid,
        execution_id: Uuid,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
        inputs: JsonValue,
        accumulated_snapshot: Option<Arc<JsonValue>>,
        trigger_input: Option<JsonValue>,
        _execution_sandbox: Option<Arc<cap_std::fs::Dir>>,
    ) -> (NodeIndex, Result<JsonValue, String>) {
        let module_id_resolved = self.resolve_module_id(node_id);

        let wasm_module = match self.fetch_module(node_id).await {
            Ok(m) => m,
            Err(e) => return (node_idx, Err(e)),
        };

        // Absent-policy fallback is METHOD-AWARE, not a blanket count:
        // a node with no explicit retry config retries transient
        // failures only when its module is read-only / pure compute
        // (worlds minimal/secrets, or http/agent with GET/HEAD-only
        // methods). Side-effect-capable modules fail closed to 0 so a
        // retry can never double-fire a send. Explicit per-node
        // `retry_count` (including 0) always wins.
        let mut retry = self
            .node_meta
            .get(&node_id)
            .and_then(|(_, rp, _)| rp.clone())
            .unwrap_or_else(|| {
                talos_workflow_engine_core::RetryPolicy::default_for_module(
                    &wasm_module.allowed_methods,
                    Some(&wasm_module.capability_world),
                )
            });

        // Approval gate: verify an approved record exists when the
        // module declares `requires_approval_for`.
        if !wasm_module.requires_approval_for.is_empty() {
            if let Some(ref gate) = self.approval_gate {
                let approval_webhook = self
                    .node_configs
                    .get(&node_id)
                    .and_then(|cfg| cfg.get("NOTIFICATION_WEBHOOK"))
                    .and_then(|v| v.as_str());
                match gate
                    .check_or_request(
                        execution_id,
                        node_id,
                        &wasm_module.requires_approval_for,
                        approval_webhook,
                    )
                    .await
                {
                    Ok(talos_workflow_engine_core::ApprovalStatus::Approved) => {}
                    Ok(talos_workflow_engine_core::ApprovalStatus::Pending) => {
                        return (
                            node_idx,
                            Err(format!(
                                "[APPROVAL_PENDING] Execution paused: module {} requires approval for {:?}. \
                             Not a genuine failure — an approval request has been created; approve it, then retry. \
                             (Dashboards/alerts can filter on the [APPROVAL_PENDING] prefix.)",
                                node_id, wasm_module.requires_approval_for
                            )),
                        );
                    }
                    Ok(talos_workflow_engine_core::ApprovalStatus::Denied { reason }) => {
                        return (node_idx, Err(reason));
                    }
                    // Defensive `_` arm: ApprovalStatus is `#[non_exhaustive]`,
                    // so adding a new variant in a minor bump shouldn't break
                    // the build. Treat unknown variants as a hard failure
                    // — fail-closed — so an upgrade can't silently let a
                    // protected node through without explicit handling.
                    Ok(_) => {
                        return (
                            node_idx,
                            Err(format!(
                                "Approval gate returned an unrecognized status \
                                 for node {node_id}; refusing to dispatch"
                            )),
                        );
                    }
                    Err(e) => {
                        tracing::error!(%node_id, "Approval gate check failed: {}", e);
                        return (node_idx, Err(format!("Approval gate check failed: {e}")));
                    }
                }
            }
        }

        // Bind the concrete executing user_id up front. It's the same id the
        // module fetcher used to pre-warm the redis cache (fetch_module ->
        // get_module_for_execution(module_id, user_id)), so the `redis:wasm:`
        // URI emitted below resolves the exact key the registry wrote.
        let user_id = match self.user_id {
            Some(uid) => uid,
            None => {
                return (
                    node_idx,
                    Err("Module execution requires user context (user_id not set)".to_string()),
                );
            }
        };

        // Module-level config from the artifact, merged with any
        // graph-JSON-level node config (graph JSON wins; reserved
        // engine keys are filtered out before the merge lands on the
        // worker).
        let module_config = wasm_module
            .config
            .clone()
            .unwrap_or_else(|| serde_json::json!({}));
        let module_config = if let Some(node_cfg) = self.node_configs.get(&node_id) {
            if module_config.is_object() && node_cfg.is_object() {
                let mut merged = module_config.as_object().cloned().unwrap_or_default();
                if let Some(node_cfg_obj) = node_cfg.as_object() {
                    for (k, v) in node_cfg_obj {
                        if k == "__skip_condition"
                            || k == "skip_condition"
                            || k == "__continue_on_error"
                            || k == "continue_on_error"
                        {
                            continue;
                        }
                        merged.insert(k.clone(), v.clone());
                    }
                }
                serde_json::Value::Object(merged)
            } else if module_config == serde_json::json!({}) {
                node_cfg.clone()
            } else {
                module_config
            }
        } else {
            module_config
        };

        // Opt-in idempotency (Task 3). Resolve the node's declared idempotency
        // key from its merged config, then STRIP `__idempotency_key__` so the
        // engine-only directive never reaches guest code as module input. The
        // key travels to the worker HMAC-bound on `JobRequest.idempotency_key`,
        // not in the payload.
        let mut module_config = module_config;
        let idempotency_key = talos_workflow_engine_core::reserved_keys::resolve_idempotency_key(
            Some(&module_config),
            &execution_id,
            &node_id,
        );
        if let Some(obj) = module_config.as_object_mut() {
            obj.remove(talos_workflow_engine_core::reserved_keys::IDEMPOTENCY_KEY);
        }

        // When idempotency IS declared, a declared Idempotency-Key header makes
        // an otherwise-non-idempotent send safe to retry at the HTTP boundary.
        // The decision (upgrade 0→transient only for HTTP-egress worlds, never
        // lower an explicit count, NEVER touch a non-declaring node) lives in
        // `effective_retries_with_idempotency` so its safety property is unit
        // tested there.
        retry.max_retries = talos_workflow_engine_core::effective_retries_with_idempotency(
            retry.max_retries,
            &wasm_module.capability_world,
            idempotency_key.is_some(),
        );

        // Merge config and input into a flat object so templates can
        // find their fields at the top level (e.g., "text", "URL").
        // Also include "config" and "input" sub-objects for templates
        // that explicitly read from those keys.
        let wrapped_input = {
            let mut merged = serde_json::Map::new();
            if let Some(obj) = module_config.as_object() {
                for (k, v) in obj {
                    merged.insert(k.clone(), v.clone());
                }
            }
            if let Some(obj) = inputs.as_object() {
                for (k, v) in obj {
                    merged.insert(k.clone(), v.clone());
                }
            } else if !inputs.is_null() {
                merged.insert("input".to_string(), inputs.clone());
            }
            if module_config != serde_json::json!({}) {
                merged.insert("config".to_string(), module_config.clone());
            }
            let is_empty_object = inputs.as_object().map(|m| m.is_empty()).unwrap_or(false);
            if !inputs.is_null() && !is_empty_object {
                merged.insert("input".to_string(), inputs.clone());
            }
            if let Some(acc) = &accumulated_snapshot {
                // Deep-clone the shared snapshot only here, at the single point
                // it is materialized into the dispatched envelope. The snapshot
                // itself was built once per node-step and shared by `Arc` across
                // every concurrent in-flight dispatch.
                merged.insert("__accumulated__".to_string(), (**acc).clone());
            }
            if let Some(ref ctx) = self.actor_context {
                // Node-scoped injection: OFF → inject into every node
                // (byte-identical to the legacy path); ON → only nodes that
                // declare `needs_memory` — which now defaults to `false` for
                // pure-egress/send worlds (http/network/messaging) so curated
                // memory doesn't reach the delivery-pattern "send" leg by
                // default (an explicit `needs_memory: true` still injects).
                // The fleet-wide `ENABLE_ACTOR_CONTEXT_INJECTION` kill-switch is
                // the OUTERMOST gate — off ⇒ no node ever receives context,
                // regardless of how `self.actor_context` got set.
                if talos_config::actor_context_injection_enabled()
                    && talos_workflow_engine_core::reserved_keys::should_inject_actor_context(
                        talos_config::smart_memory_context_enabled(),
                        self.node_needs_memory_for_world(node_id, &wasm_module.capability_world),
                    )
                {
                    merged.insert("__actor_context__".to_string(), ctx.clone());
                }
            }
            // Input-freshness contract: when this node declares `requires_fresh`,
            // answer with a `__staleness__` report so it can never present stale
            // memory as current. `None` = no contract (zero cost, unchanged
            // behavior). `on_stale: "fail"` short-circuits the dispatch with a
            // real error instead of a plausible-looking wrong answer.
            if let Some((report, must_fail)) = self.resolve_node_staleness(node_id).await {
                if must_fail {
                    let detail =
                        talos_workflow_engine_core::reserved_keys::describe_stale_entries(&report);
                    return (
                        node_idx,
                        Err(format!(
                            "input freshness contract violated (on_stale=fail): {detail}"
                        )),
                    );
                }
                merged.insert("__staleness__".to_string(), report);
            }
            // `__trigger_input__` survives every hop — including across
            // sub-workflow boundaries when the dispatcher wraps the child
            // trigger with `__trigger_input__: parent_ti`. Injecting it
            // here keeps the scaffold's "always preserved" contract true
            // for every node in every workflow.
            if let Some(ref ti) = trigger_input {
                merged.insert("__trigger_input__".to_string(), ti.clone());
            }
            serde_json::Value::Object(merged)
        };

        // Truncated input preview for the node-I/O inspector.
        // Walk back from the requested byte cap to the nearest UTF-8
        // char boundary — slicing by bytes alone panics when the cut
        // lands inside a multi-byte character (e.g. an em-dash in an
        // INJECT_CONTEXT actor-memory payload, real prod symptom
        // 2026-04-29 hit by aegix-ceo's `/watch-semgrep` workflow).
        // `is_char_boundary` is stable; `floor_char_boundary` would
        // be cleaner but is still unstable as of Rust 1.95 nightly
        // (issue #93743).
        {
            let input_preview = {
                let s = serde_json::to_string(&wrapped_input).unwrap_or_default();
                if s.len() > 4096 {
                    let mut safe_end = 4096;
                    while safe_end > 0 && !s.is_char_boundary(safe_end) {
                        safe_end -= 1;
                    }
                    format!("{}...(truncated)", &s[..safe_end])
                } else {
                    s
                }
            };
            emit_event_spawn(
                &self.event_sink,
                NodeEventWrite {
                    execution_id,
                    event_type: "node_input".to_string(),
                    node_id: Some(node_id),
                    status: "Input".to_string(),
                    log_message: Some(input_preview),
                    iteration_index: None,
                    error_class: None,
                },
            );
        }

        let job_id = Uuid::new_v4();
        if let Some(ref store) = self.module_execution_store {
            // Resolve the actual wasm_modules.id for the FK.
            // `module_id_resolved` may be a node_template UUID
            // (Fallback 2 path) not present in wasm_modules; the
            // store's resolver maps template → wasm_modules by
            // most-recent compile.
            let actual_module_id = store.resolve_module_id(module_id_resolved).await;
            if let Err(db_err) = store
                .record_started(ExecutionStartedContext {
                    id: job_id,
                    module_id: actual_module_id,
                    // The `user_id` bound at the top of this function, NOT a
                    // minted fallback. `self.user_id.unwrap_or_else(Uuid::
                    // new_v4)` stood here and was read (twice, in two separate
                    // reviews) as a guaranteed FK violation against `users`.
                    // It was not: the `None` arm is unreachable — the match at
                    // the top of this function early-returns on `None`, the
                    // receiver is `&self`, and `user_id` is a plain
                    // `Option<Uuid>` field with no interior mutability, so it
                    // cannot become `None` in between. Using the bound local
                    // makes that structural rather than something the next
                    // reader has to re-derive.
                    user_id,
                    workflow_execution_id: execution_id,
                    input: &inputs,
                    trigger_type: "webhook",
                    // Race-safe: if a sibling has already failed the
                    // workflow, this row enters as 'cancelled' rather
                    // than 'running', closing the race with the
                    // failure-path UPDATE.
                    race_safe_status: true,
                    // Attribute the module run to the workflow's actor.
                    actor_id: self.actor_id,
                })
                .await
            {
                tracing::error!("module_execution_store.record_started failed: {}", db_err);
            }
        }

        // Per-node fuel limit: config override > module default, then the
        // adaptive learned ceiling applied as a floor, clamped to
        // `self.max_fuel_per_node`. Single decision point shared with the
        // pipeline + loop paths (see `resolve_node_max_fuel`).
        let node_max_fuel = self.resolve_node_max_fuel(
            &node_id,
            module_config.get("max_fuel").and_then(|v| v.as_u64()),
            wasm_module.max_fuel,
        );

        // Resolve secrets. RFC 0010 P3 (D3b): `build_dispatch_secrets_for` is the
        // single decision point — under claim-based sealing it returns the
        // PLAINTEXT map (registered in `InFlightSeals`, sealed on the worker's
        // claim; NO plaintext on the wire), otherwise the legacy inline WSK
        // envelope. The SAME helper backs the loop-body path so sealing applies
        // uniformly. L-1: AAD = execution_id binds the legacy AES-GCM tag.
        let secrets = match (self.secrets_resolver.as_ref(), &worker_shared_key) {
            (Some(resolver), Some(key)) => {
                let vault_paths = extract_vault_paths(&module_config);
                crate::secrets_pipeline::build_dispatch_secrets_for(
                    resolver.as_ref(),
                    self.secret_envelope.as_ref(),
                    module_id_resolved,
                    self.user_id,
                    &vault_paths,
                    &wasm_module.allowed_secrets,
                    key.as_bytes(),
                    self.max_llm_tier,
                    execution_id.as_bytes(),
                )
                .await
            }
            _ => crate::secrets_pipeline::DispatchSecrets::default(),
        };
        let (encrypted_secrets, plaintext_secrets, secret_paths) =
            (secrets.encrypted, secrets.plaintext, secrets.secret_paths);

        // Wire-format WASM budget. The dispatcher internally adds its
        // own Tokio-outer grace on top (see TOKIO_WRAP_GRACE_SECS).
        let node_timeout_secs = self
            .node_timeouts
            .get(&node_id)
            .copied()
            .unwrap_or(*DEFAULT_NODE_TIMEOUT_SECS);

        let job = DispatchJob {
            execution_id,
            node_id,
            module_id: module_id_resolved,
            // Pre-INSERTed module_executions row is keyed by this id.
            job_id: Some(job_id),
            user_id: self.user_id,
            actor_id: self.actor_id,
            // User-scoped redis URI (L-27): the worker strips `redis:` and
            // GETs `wasm:{user_id}:{module_id}` — the exact key the registry
            // pre-warmed under this same user during fetch_module above. No
            // more non-scoped `wasm:{module_id}` shadow key.
            module_uri: wasm_module.oci_url.clone().unwrap_or_else(|| {
                talos_workflow_engine_core::scoped_wasm_redis_uri(user_id, module_id_resolved)
            }),
            // Embed bytes directly (no Redis pre-warm dependency) when they
            // fit under the NATS-payload-aware cap; oversized components
            // (interpreter toolchains: componentize-py/jco, 12-18MB) route
            // by the `redis:wasm:` URI — see `dispatch_bytes` for the
            // transport + integrity story.
            wasm_bytes: if crate::dispatch_bytes::embeds_inline(&wasm_module.wasm_bytes) {
                Some(wasm_module.wasm_bytes.clone())
            } else {
                None
            },
            // URI-fetched bytes (OCI modules AND oversized components)
            // commit the expected hash so the worker verifies fetched
            // content matches what the engine compiled. Inline bytes don't
            // need this — HMAC already covers sha256(inline_bytes).
            expected_wasm_hash: if crate::dispatch_bytes::embeds_inline(&wasm_module.wasm_bytes) {
                None
            } else {
                Some(wasm_module.content_hash.clone())
            },
            capability_world: Some(wasm_module.capability_world.clone()),
            integration_name: wasm_module.integration_name.clone(),
            input_payload: wrapped_input,
            timeout: std::time::Duration::from_secs(node_timeout_secs),
            max_fuel: node_max_fuel,
            allowed_hosts: wasm_module.allowed_hosts.clone(),
            allowed_methods: wasm_module.allowed_methods.clone(),
            allowed_secrets: wasm_module.allowed_secrets.clone(),
            allowed_sql_operations: vec![],
            allow_tier2_exposure: false,
            encrypted_secrets_ciphertext: encrypted_secrets.ciphertext,
            encrypted_secrets_nonce: encrypted_secrets.nonce,
            plaintext_secrets,
            secret_paths,
            priority: 100,
            dry_run: self.dry_run,
            max_llm_tier: self.max_llm_tier,
            max_write_ceiling: self.max_write_ceiling,
            egress_scope: self.egress_scope,
            idempotency_key,
            max_retries: retry.max_retries,
            backoff_ms: retry.backoff_ms,
            retry_condition: retry.retry_condition.clone(),
            retry_delay_expr: retry.retry_delay_expression.clone(),
            emit_retry_events: true,
        };

        // Wall clock for the ledger row's `duration_ms`. Started immediately
        // before the dispatch so it measures the same span the pipeline path
        // reports as `execution_time_ms` and the loop path measures with its
        // own `iter_started.elapsed()` — dispatch + worker run + any retry
        // backoff, not the config/secret resolution above it.
        //
        // SAY WHAT THIS NUMBER ACTUALLY BECOMES, because the name promises
        // more than it delivers. `module_executions` carries a BEFORE UPDATE
        // trigger (`calculate_module_execution_duration`) that OVERWRITES
        // `duration_ms` with `completed_at - started_at` whenever
        // `completed_at` transitions off NULL — which is exactly the first
        // finalize. So on the row's first terminal write the value measured
        // here is discarded and the stored number is wall time from the
        // `record_started` INSERT instead. The two differ only by the
        // secret-resolution and config-merge work between them (small, and
        // arguably the honest thing to include), so this is left as-is rather
        // than changed under a fix about something else. It is stated because
        // the same trigger is what turned the sweep's `completed_at = NOW()`
        // into the fabricated 1,800,301 ms minimum this change exists to
        // stop, and the pipeline path's `execution_time_ms` has always been
        // discarded the same way.
        let dispatch_started = std::time::Instant::now();
        let outcome = dispatcher.dispatch(job).await;
        let duration_ms = i32::try_from(dispatch_started.elapsed().as_millis()).unwrap_or(i32::MAX);

        // THE 2026-08-12 finding: this arm used to return without ever closing
        // the `module_executions` row `record_started` opened ~140 lines above.
        // The loop path (`complete_loop_iteration_row`) and the pipeline path
        // (`engine_dispatch_pipeline`) both finalize their rows; single-node
        // dispatch — by volume, nearly every row in the table — did not. The
        // row therefore sat in `'running'` until the 30-minute stuck-execution
        // sweep rewrote it to `'timeout'` with `error_type='stuck'`, so every
        // successful workflow node was recorded as a dead worker and its
        // `duration_ms` recorded *time until the sweep noticed*, not work time.
        // Downstream that emptied `WHERE status='completed'` populations
        // outright: `replay_module_regression`'s corpus and
        // `find_latest_completed_execution_io` have both been silently
        // returning nothing for as long as the table has had rows.
        match outcome {
            Ok(result) => {
                tracing::info!(%node_id, "Node execution succeeded");
                self.finalize_module_execution_row(
                    job_id,
                    "completed",
                    &result.output,
                    duration_ms,
                    None,
                )
                .await;
                (node_idx, Ok(result.output))
            }
            Err(e) => {
                let message = e.to_string();
                self.finalize_module_execution_row(
                    job_id,
                    classify_dispatch_failure_status(&message),
                    &JsonValue::Null,
                    duration_ms,
                    Some(&message),
                )
                .await;
                (node_idx, Err(message))
            }
        }
    }

    /// Close out one `module_executions` row — the single chokepoint every
    /// engine dispatch path uses to move a row it opened with
    /// `record_started` into a terminal state.
    ///
    /// Consolidated 2026-08-12: single-node dispatch had no finalize at all,
    /// and the loop / pipeline paths each carried their own copy of the
    /// redact-then-record-then-log-on-error shape.
    ///
    /// STATE THE INVARIANT PRECISELY, because the loose version of it is what
    /// let a second instance of the same bug ship inside the fix. A chokepoint
    /// does NOT by itself make "did this path finalize?" a one-place question;
    /// what does is the invariant **every control-flow exit below a
    /// `record_started` must pass through this function**. Reviewing the fix
    /// found `engine_dispatch_pipeline`'s `dispatch_chain` error arm doing a
    /// bare `return` under N already-INSERTed step rows — a call site of this
    /// chokepoint that simply was not on that path. So when adding an early
    /// exit anywhere below a `record_started`, the question to ask is not
    /// "does this file call the chokepoint?" but "does THIS exit?".
    ///
    /// The three engine paths and their exits, as of 2026-08-13:
    /// * single-node — both match arms on `dispatcher.dispatch`.
    /// * loop — both match arms per iteration, including the `__error`-envelope
    ///   break (`complete_loop_iteration_row`).
    /// * pipeline — the `dispatch_chain` Err arm, the per-step result loop, and
    ///   the aborted-trailing-step loop. Its EIGHT other returns (two on user
    ///   context, one on module fetch, four on the approval gate, one on the
    ///   freshness contract) all sit ABOVE its `record_started` loop — no row
    ///   is open yet — which is why they are correct as bare returns.
    ///
    /// Payload/error redaction here is deliberate defense in depth: the
    /// Postgres store redacts again at the bind boundary.
    ///
    /// Best-effort by contract. A finalize failure must NOT fail the job —
    /// the node already ran and its result is already in the caller's hands.
    /// The stuck-execution sweep remains the backstop for a row this never
    /// reaches (a dropped reactor future under a workflow-level wall-clock
    /// timeout, a DB outage during this write).
    pub(crate) async fn finalize_module_execution_row(
        &self,
        id: Uuid,
        status: &str,
        output: &JsonValue,
        duration_ms: i32,
        error_message: Option<&str>,
    ) {
        let Some(ref store) = self.module_execution_store else {
            return;
        };
        let redacted_error = error_message.map(|e| self.redact_str(e));
        if let Err(db_err) = store
            .record_completed(
                id,
                status,
                &self.redact_json(output),
                duration_ms,
                redacted_error.as_deref(),
            )
            .await
        {
            tracing::error!(
                module_execution_id = %id,
                status,
                "module_execution_store.record_completed failed: {}",
                db_err
            );
        }
    }
}

/// Map a single-node dispatch failure onto a `module_executions.status`.
///
/// Deliberately NARROW: only the dispatcher's own timeout sentinel
/// (`"Job execution timed out"`, returned by both `execute_job_with_retry`
/// and `dispatch_with_retry` in `talos-workflow-engine-nats`) is recorded as
/// `'timeout'`. Everything else is `'failed'`.
///
/// A substring search for "timeout" would be wrong in the direction that
/// matters: a module whose own HTTP call timed out returns an application
/// error whose text says "timeout", and recording that as a worker-level
/// timeout fabricates a signal an operator would then chase. Under-reporting
/// timeouts as failures loses a distinction; over-reporting invents one. The
/// cost of this narrowness is that a future dispatcher timeout string that
/// does not match lands in `'failed'` — still terminal, still not a sweep
/// artefact, which is what this whole change is about.
pub(crate) fn classify_dispatch_failure_status(error: &str) -> &'static str {
    if error.contains("Job execution timed out") {
        "timeout"
    } else {
        "failed"
    }
}

#[cfg(test)]
mod single_node_ledger_finalize_tests {
    //! D5 guard: a dispatched single node must leave its `module_executions`
    //! row in a TERMINAL state.
    //!
    //! Regression cover for the 2026-08-12 finding. `run_single_node_dispatch`
    //! opened a row with `record_started` and never closed it, so the
    //! 30-minute stuck-execution sweep rewrote every one of them to
    //! `'timeout'` / `error_type='stuck'`. Live evidence at the time of the
    //! fix: 21,065 `timeout` rows, 0 `completed` rows EVER, and 20,252 of the
    //! timeouts had a parent `workflow_executions` row whose status was
    //! `completed`.
    //!
    //! These tests drive the REAL `run_single_node_dispatch` (not a
    //! re-implementation of its tail) through the in-memory adapters and
    //! assert on the recorded store calls. They FAIL on the pre-fix tree:
    //! before the fix the store saw exactly one call — `Started` — and no
    //! `Completed` for any outcome.
    //!
    //! What they deliberately do NOT prove: that the Postgres UPDATE lands.
    //! `CaptureModuleExecutionStore` records the call, it does not write a
    //! row. The status guard that makes the write idempotent lives in
    //! `talos-engine`'s `PostgresModuleExecutionStore` and is covered there
    //! and end-to-end against the live stack, not here.

    use std::sync::Arc;

    use petgraph::graph::NodeIndex;
    use serde_json::json;
    use talos_workflow_engine_core::{NodeDispatcher, WasmModuleArtifact};
    use talos_workflow_engine_test_utils::capture::{
        CaptureModuleExecutionStore, ExecutionStoreCall,
    };
    use talos_workflow_engine_test_utils::dispatch::ScriptedDispatcher;
    use talos_workflow_engine_test_utils::memory::InMemoryModuleFetcher;
    use uuid::Uuid;

    use crate::engine::ParallelWorkflowEngine;

    fn stub_artifact(module_id: Uuid) -> WasmModuleArtifact {
        WasmModuleArtifact {
            module_id,
            content_hash: "stub".into(),
            wasm_bytes: vec![1, 2, 3],
            oci_url: None,
            max_fuel: 1_000_000,
            capability_world: "stub".into(),
            allowed_hosts: vec![],
            allowed_methods: vec![],
            allowed_secrets: vec![],
            requires_approval_for: vec![],
            integration_name: None,
            config: None,
        }
    }

    fn engine_with_node(
        node_id: Uuid,
        module_id: Uuid,
        store: Arc<CaptureModuleExecutionStore>,
    ) -> ParallelWorkflowEngine {
        let mut engine = ParallelWorkflowEngine::new();
        engine.set_user_id(Uuid::new_v4());
        // Bare `set_actor_id` needs no opt-out: lint check 29 excludes
        // `talos-workflow-engine/**` wholesale.
        engine.set_actor_id(Uuid::new_v4());
        engine.set_module_execution_store(store);
        engine.set_module_fetcher(Arc::new(
            InMemoryModuleFetcher::new().with_module(module_id, stub_artifact(module_id)),
        ));
        engine.add_node(node_id, Some(module_id), None, None);
        engine
    }

    /// `node_idx` is a pass-through: `run_single_node_dispatch` only ever
    /// returns it, never indexes the graph with it. A literal keeps the test
    /// from depending on private graph internals.
    const PASSTHROUGH_IDX: usize = 0;

    async fn dispatch_once(
        dispatcher: Arc<dyn NodeDispatcher>,
        store: Arc<CaptureModuleExecutionStore>,
        node_id: Uuid,
        module_id: Uuid,
    ) -> Result<serde_json::Value, String> {
        let engine = engine_with_node(node_id, module_id, store);
        engine
            .run_single_node_dispatch(
                NodeIndex::new(PASSTHROUGH_IDX),
                node_id,
                Uuid::new_v4(),
                dispatcher,
                None,
                json!({ "seed": 1 }),
                None,
                None,
                None,
            )
            .await
            .1
    }

    fn terminal_calls(store: &CaptureModuleExecutionStore) -> Vec<(Uuid, String)> {
        store
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                ExecutionStoreCall::Completed { id, status, .. } => Some((id, status)),
                _ => None,
            })
            .collect()
    }

    fn started_ids(store: &CaptureModuleExecutionStore) -> Vec<Uuid> {
        store
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                ExecutionStoreCall::Started { id, .. } => Some(id),
                _ => None,
            })
            .collect()
    }

    /// THE regression. A successful node closes its own row as `completed` —
    /// and closes the SAME row it opened, not merely "some" row.
    #[tokio::test]
    async fn a_successful_node_finalizes_the_row_it_opened() {
        let store = Arc::new(CaptureModuleExecutionStore::new());
        let node_id = Uuid::new_v4();
        let module_id = Uuid::new_v4();
        let dispatcher: Arc<dyn NodeDispatcher> =
            Arc::new(ScriptedDispatcher::new().with_response(module_id, json!({ "ok": true })));

        let out = dispatch_once(dispatcher, store.clone(), node_id, module_id).await;
        assert_eq!(out.expect("dispatch succeeded"), json!({ "ok": true }));

        let opened = started_ids(&store);
        assert_eq!(opened.len(), 1, "one start row per single-node dispatch");
        let closed = terminal_calls(&store);
        assert_eq!(
            closed.len(),
            1,
            "the row must be finalized exactly once — pre-fix this was 0 and the \
             30-minute stuck sweep rewrote the row to 'timeout'/'stuck'"
        );
        assert_eq!(closed[0].0, opened[0], "finalized the row it opened");
        assert_eq!(
            closed[0].1, "completed",
            "a successful node is 'completed' — the status \
             `replay_module_regression`'s corpus selects on"
        );
    }

    /// The output the caller receives is the output recorded. A `completed`
    /// row with no payload is what a backfill would have produced, and it is
    /// useless as a replay baseline.
    #[tokio::test]
    async fn the_finalized_row_carries_the_dispatch_output() {
        let store = Arc::new(CaptureModuleExecutionStore::new());
        let node_id = Uuid::new_v4();
        let module_id = Uuid::new_v4();
        let dispatcher: Arc<dyn NodeDispatcher> =
            Arc::new(ScriptedDispatcher::new().with_response(module_id, json!({ "answer": 42 })));

        dispatch_once(dispatcher, store.clone(), node_id, module_id)
            .await
            .expect("dispatch succeeded");

        let recorded = store
            .calls()
            .into_iter()
            .find_map(|c| match c {
                ExecutionStoreCall::Completed { output, .. } => Some(output),
                _ => None,
            })
            .expect("a terminal call was recorded");
        assert_eq!(
            recorded,
            json!({ "answer": 42 }),
            "an output-less 'completed' row is an empty replay baseline"
        );
    }

    /// A failing node is `failed`, not left for the sweep to call `timeout`.
    /// The distinction is the whole point: pre-fix EVERY outcome became
    /// `timeout`/`stuck`, so "the worker died" and "the module returned an
    /// error" were indistinguishable in the ledger.
    #[tokio::test]
    async fn a_failing_node_finalizes_as_failed_not_timeout() {
        let store = Arc::new(CaptureModuleExecutionStore::new());
        let node_id = Uuid::new_v4();
        let module_id = Uuid::new_v4();
        let dispatcher: Arc<dyn NodeDispatcher> = Arc::new(
            ScriptedDispatcher::new().with_error(module_id, "boom: module returned error"),
        );

        let out = dispatch_once(dispatcher, store.clone(), node_id, module_id).await;
        assert!(out.is_err(), "scripted error propagates to the caller");

        let closed = terminal_calls(&store);
        assert_eq!(closed.len(), 1, "a failing node still closes its row");
        assert_eq!(closed[0].1, "failed");
    }

    /// The dispatcher's own timeout sentinel — and ONLY it — records
    /// `'timeout'`.
    #[test]
    fn dispatch_failure_status_classification_is_narrow() {
        use super::classify_dispatch_failure_status as classify;
        assert_eq!(classify("Job execution timed out"), "timeout");
        assert_eq!(
            classify("Job dispatch failed after 3 attempts: Job execution timed out"),
            "timeout"
        );
        // A module's OWN error text mentioning a timeout must not be
        // laundered into a worker-level timeout.
        assert_eq!(
            classify("Job failed (non-transient: auth): upstream connection timeout"),
            "failed"
        );
        assert_eq!(classify("Missing AUTH_HEADER config"), "failed");
    }
}
