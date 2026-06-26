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
use crate::secrets_pipeline::{build_encrypted_secrets_for, extract_vault_paths};

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
        let retry = self
            .node_meta
            .get(&node_id)
            .and_then(|(_, rp, _)| rp.clone())
            .unwrap_or_default();

        let wasm_module = match self.fetch_module(node_id).await {
            Ok(m) => m,
            Err(e) => return (node_idx, Err(e)),
        };

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

        if self.user_id.is_none() {
            return (
                node_idx,
                Err("Module execution requires user context (user_id not set)".to_string()),
            );
        }

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
                merged.insert("__actor_context__".to_string(), ctx.clone());
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
                    user_id: self.user_id.unwrap_or_else(Uuid::new_v4),
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

        // Per-node fuel limit: config override > module default,
        // clamped to `self.max_fuel_per_node` (engine-configurable;
        // see `set_max_fuel_per_node`).
        let node_max_fuel = module_config
            .get("max_fuel")
            .and_then(|v| v.as_u64())
            .unwrap_or(wasm_module.max_fuel)
            .min(self.max_fuel_per_node);

        // Resolve encrypted secrets payload (opaque bytes at this layer).
        // L-1: AAD = execution_id binds the AES-GCM tag to this dispatch.
        let encrypted_secrets = match (self.secrets_resolver.as_ref(), &worker_shared_key) {
            (Some(resolver), Some(key)) => {
                let vault_paths = extract_vault_paths(&module_config);
                build_encrypted_secrets_for(
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
            _ => Default::default(),
        };

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
            module_uri: wasm_module
                .oci_url
                .clone()
                .unwrap_or_else(|| format!("redis:wasm:{module_id_resolved}")),
            // Embed bytes directly so the worker doesn't depend on
            // Redis pre-warm — bypasses the `wasm:{uid}:{id}` vs
            // `wasm:{id}` key mismatch and template-UUID issues.
            wasm_bytes: if wasm_module.wasm_bytes.is_empty() {
                None
            } else {
                Some(wasm_module.wasm_bytes.clone())
            },
            // OCI modules (empty wasm_bytes) commit the expected hash
            // so the worker verifies fetched content matches what the
            // engine compiled. Inline bytes don't need this — HMAC
            // already covers sha256(inline_bytes).
            expected_wasm_hash: if wasm_module.wasm_bytes.is_empty() {
                Some(wasm_module.content_hash.clone())
            } else {
                None
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
            priority: 100,
            dry_run: self.dry_run,
            max_llm_tier: self.max_llm_tier,
            max_retries: retry.max_retries,
            backoff_ms: retry.backoff_ms,
            retry_condition: retry.retry_condition.clone(),
            retry_delay_expr: retry.retry_delay_expression.clone(),
            emit_retry_events: true,
        };

        match dispatcher.dispatch(job).await {
            Ok(result) => {
                tracing::info!(%node_id, "Node execution succeeded");
                (node_idx, Ok(result.output))
            }
            Err(e) => (node_idx, Err(e.to_string())),
        }
    }
}
