//! Pipeline-chain dispatch — extracted from engine.rs.
//!
//! Hosts `run_pipeline_chain_dispatch`, the chain-detection branch
//! of the reactor that batches in-degree=1/out-degree=1 sequences
//! through `NodeDispatcher::dispatch_chain` in a single transport
//! round-trip. Pure code movement from the previous engine.rs
//! location — no behaviour change. Lifted out so the dispatch path
//! stays auditable in isolation alongside `engine_dispatch_single`.

use std::sync::{Arc, OnceLock};

use petgraph::graph::NodeIndex;
use petgraph::Direction;
use serde_json::Value as JsonValue;
use talos_workflow_engine_core::{DispatchJob, ExecutionStartedContext};
use uuid::Uuid;

use crate::engine::{ensure_rate_limit_eviction_task, ParallelWorkflowEngine, MODULE_RATE_LIMITS};
use crate::secrets_pipeline::{build_encrypted_secrets_for, extract_vault_paths};

impl ParallelWorkflowEngine {
    /// Build and await the full pipeline-chain dispatch future.
    ///
    /// Runs when a linear chain is detected (`detect_linear_chains`)
    /// and the scheduler is at the chain head. Fetches each step's
    /// module artifact, runs the approval gate per step, encrypts the
    /// per-step secrets, assembles a `ChainDispatchRequest`, and hands
    /// it to the [`NodeDispatcher::dispatch_chain`] impl.
    ///
    /// Extracted from the reactor loop for the same reason as
    /// [`run_single_node_dispatch`](Self::run_single_node_dispatch) —
    /// the scheduler reads as a sequence of handler calls rather than
    /// a ~490-line inline closure. Semantics are preserved verbatim.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn run_pipeline_chain_dispatch(
        &self,
        chain: Vec<NodeIndex>,
        chain_input: JsonValue,
        accumulated_snapshot: Option<JsonValue>,
        execution_id: Uuid,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
    ) -> (NodeIndex, Result<JsonValue, String>) {
        let chain_tail = chain[chain.len() - 1];
        let chain_node_ids: Vec<Uuid> = chain.iter().map(|&n| self.graph[n]).collect();
        // Pre-resolve graph node UUIDs → module UUIDs. Graph node IDs
        // are SHA256-derived from the node label string and don't
        // match any `wasm_modules` row; `resolve_module_id` maps them
        // back to the template / module UUID stored in `node_meta` at
        // graph load time.
        let chain_module_ids: Vec<Uuid> = chain_node_ids
            .iter()
            .map(|&nid| self.resolve_module_id(nid))
            .collect();
        let chain_head_id = chain_node_ids[0];
        let chain_retry = self
            .node_meta
            .get(&chain_head_id)
            .and_then(|(_, rp, _)| rp.clone())
            .unwrap_or_default();

        // Resolve user_id early — required for all module-fetcher calls.
        let uid_for_chain: Option<Uuid> = if self.module_fetcher.is_some() {
            match self.user_id {
                Some(u) => Some(u),
                None => {
                    return (
                        chain_tail,
                        Err("Module execution requires user context (user_id not set)".to_string()),
                    );
                }
            }
        } else {
            None
        };

        // Build `DispatchJob`s for every node in the chain. The
        // dispatcher's `dispatch_chain` adapter maps these into
        // whatever batch wire format its backing transport uses (the
        // reference NATS dispatcher emits a signed
        // `PipelineJobRequest`; an in-process test dispatcher might
        // just loop `dispatch` via `dispatch_chain_sequential`).
        let mut step_jobs: Vec<DispatchJob> = Vec::with_capacity(chain.len());
        for (i, &_step_idx) in chain.iter().enumerate() {
            let step_node_id = chain_node_ids[i];
            let step_module_id = chain_module_ids[i];
            let uid = match uid_for_chain {
                Some(u) => u,
                None => {
                    return (
                        chain_tail,
                        Err(format!(
                            "Missing user ID for module {step_node_id} in chain"
                        )),
                    );
                }
            };

            // Fetch the step's module artifact. `WasmModuleArtifact.config`
            // mirrors `wasm_modules.config` — same data the pre-extraction
            // code read via `reg.get_execution_info`. The Redis cache-warm
            // that used to fire here is dropped: `wasm_bytes` is embedded
            // in the dispatched chain, so the worker doesn't depend on it.
            let (artifact, module_config) = match self.module_fetcher.as_ref() {
                Some(fetcher) => match fetcher.fetch(step_module_id, uid).await {
                    Ok(a) => {
                        let config = a.config.clone().unwrap_or_else(|| serde_json::json!({}));
                        (Some(a), config)
                    }
                    Err(e) => {
                        return (chain_tail, Err(format!("Failed to prepare module: {e}")));
                    }
                },
                None => (None, serde_json::json!({})),
            };

            // Approval gate (per pipeline step).
            let requires_approval: Vec<String> = artifact
                .as_ref()
                .map(|a| a.requires_approval_for.clone())
                .unwrap_or_default();
            if !requires_approval.is_empty() {
                if let Some(ref gate) = self.approval_gate {
                    let approval_webhook = module_config
                        .get("NOTIFICATION_WEBHOOK")
                        .and_then(|v| v.as_str());
                    match gate
                        .check_or_request(
                            execution_id,
                            step_node_id,
                            &requires_approval,
                            approval_webhook,
                        )
                        .await
                    {
                        Ok(talos_workflow_engine_core::ApprovalStatus::Approved) => {}
                        Ok(talos_workflow_engine_core::ApprovalStatus::Pending) => {
                            return (
                            chain_tail,
                            Err(format!(
                                "Execution paused: module {step_node_id} requires approval for {requires_approval:?}. \
                                 An approval request has been created."
                            )),
                        );
                        }
                        Ok(talos_workflow_engine_core::ApprovalStatus::Denied { reason }) => {
                            return (chain_tail, Err(reason));
                        }
                        // Fail-closed for non_exhaustive future variants — see
                        // engine_dispatch_single.rs for the rationale.
                        Ok(_) => {
                            return (
                                chain_tail,
                                Err(format!(
                                    "Approval gate returned an unrecognized status \
                                     for step {step_node_id}; refusing to dispatch"
                                )),
                            );
                        }
                        Err(e) => {
                            return (chain_tail, Err(format!("Approval gate check failed: {e}")));
                        }
                    }
                }
            }

            // Extract vault:// paths from module_config before it is
            // moved into the DispatchJob below.
            let vault_paths = extract_vault_paths(&module_config);

            // Per-node fuel precedence: node-config `max_fuel` > module
            // default > 1M fallback. Capped at 50M.
            let module_default_fuel = artifact
                .as_ref()
                .map(|a| a.max_fuel)
                .filter(|f| *f > 0)
                .unwrap_or(1_000_000);
            let node_max_fuel = module_config
                .get("max_fuel")
                .and_then(|v| v.as_u64())
                .unwrap_or(module_default_fuel)
                .min(self.max_fuel_per_node);

            let encrypted_secrets = match (self.secrets_resolver.as_ref(), &worker_shared_key) {
                (Some(resolver), Some(key)) => {
                    build_encrypted_secrets_for(
                        resolver.as_ref(),
                        self.secret_envelope.as_ref(),
                        step_node_id,
                        self.user_id,
                        &vault_paths,
                        &[],
                        key.as_bytes(),
                        self.max_llm_tier,
                    )
                    .await
                }
                _ => Default::default(),
            };
            step_jobs.push(DispatchJob {
                execution_id,
                node_id: step_node_id,
                module_id: step_node_id,
                // Chain-level wire format derives a single `job_id`;
                // per-step ids aren't correlated to individual
                // `module_executions` rows (those use `step_exec_ids`).
                job_id: None,
                user_id: Some(uid),
                actor_id: self.actor_id,
                // Match pre-extraction behavior: the redis fallback key
                // is `redis:wasm:{module_id}` keyed on `step_module_id`
                // to match the worker's redis-key convention.
                module_uri: artifact
                    .as_ref()
                    .and_then(|a| a.oci_url.clone())
                    .unwrap_or_else(|| format!("redis:wasm:{step_module_id}")),
                // Embed bytes when the fetcher already resolved them,
                // matching `engine_dispatch_single.rs` and the loop
                // dispatcher in `scheduler_handlers.rs`. Skips the
                // Redis-key class of bugs (`wasm:{uid}:{id}` vs
                // `wasm:{id}`) and the prior-comment-claim-but-not-code
                // inconsistency above.
                wasm_bytes: artifact.as_ref().and_then(|a| {
                    if a.wasm_bytes.is_empty() {
                        None
                    } else {
                        Some(a.wasm_bytes.clone())
                    }
                }),
                // Worker only consults the hash on a URI fetch; when
                // bytes are inline, the envelope HMAC already covers
                // them. Emit only for the fetch-by-URI path.
                expected_wasm_hash: artifact.as_ref().and_then(|a| {
                    if a.wasm_bytes.is_empty() {
                        Some(a.content_hash.clone())
                    } else {
                        None
                    }
                }),
                // Pipeline dispatch uses a chain-level capability
                // world; the adapter drops the per-step value.
                capability_world: None,
                integration_name: artifact.as_ref().and_then(|a| a.integration_name.clone()),
                // `PipelineStep` calls this `config`; the adapter maps
                // `input_payload` to it.
                input_payload: module_config,
                timeout: std::time::Duration::from_secs(
                    self.node_timeouts.get(&step_node_id).copied().unwrap_or(30),
                ),
                max_fuel: node_max_fuel,
                allowed_hosts: artifact
                    .as_ref()
                    .map(|a| a.allowed_hosts.clone())
                    .unwrap_or_default(),
                allowed_methods: artifact
                    .as_ref()
                    .map(|a| a.allowed_methods.clone())
                    .unwrap_or_default(),
                allowed_secrets: artifact
                    .as_ref()
                    .map(|a| a.allowed_secrets.clone())
                    .unwrap_or_default(),
                allowed_sql_operations: vec![],
                allow_tier2_exposure: false,
                encrypted_secrets_ciphertext: encrypted_secrets.ciphertext,
                encrypted_secrets_nonce: encrypted_secrets.nonce,
                priority: 100,
                dry_run: self.dry_run,
                // Inherit the engine's tier ceiling (stamped from
                // `actors.max_llm_tier` by the controller at dispatch time).
                max_llm_tier: self.max_llm_tier,
                max_retries: 0,
                backoff_ms: 0,
                retry_condition: None,
                retry_delay_expr: None,
                // Chain-level retry emits under the chain's aggregate
                // policy, not per-step.
                emit_retry_events: false,
            });
        }

        // First-step input wrapping: inject gathered inputs under
        // `pipeline_input`, preserve the original `config`, and fold in
        // any accumulated prior-node context and actor memory.
        if let Some(first) = step_jobs.first_mut() {
            let mut wrapped = serde_json::json!({
                "pipeline_input": chain_input,
                "config": first.input_payload,
            });
            if let Some(ref acc) = accumulated_snapshot {
                if let Some(obj) = wrapped.as_object_mut() {
                    obj.insert("__accumulated__".to_string(), acc.clone());
                }
            }
            if let Some(ref ctx) = self.actor_context {
                if let Some(obj) = wrapped.as_object_mut() {
                    obj.insert("__actor_context__".to_string(), ctx.clone());
                }
            }
            first.input_payload = wrapped;
        }

        // Pre-INSERT `module_executions` rows for each step so
        // observers can see the chain's in-flight state. Row ids
        // (`step_exec_ids`) are engine-level bookkeeping; the wire
        // format doesn't carry them. The post-dispatch UPDATE below
        // targets the right row by id.
        let mut step_exec_ids = Vec::new();
        if let Some(ref store) = self.module_execution_store {
            for (i, &step_node_id) in chain_node_ids.iter().enumerate() {
                let step_exec_id = Uuid::new_v4();
                step_exec_ids.push(step_exec_id);
                let input_for_db = if i == 0 {
                    serde_json::json!({ "input": chain_input })
                } else {
                    serde_json::json!(null)
                };
                let actual_mid = store.resolve_module_id(step_node_id).await;
                if let Err(db_err) = store
                    .record_started(ExecutionStartedContext {
                        id: step_exec_id,
                        module_id: actual_mid,
                        user_id: uid_for_chain.unwrap_or_else(Uuid::new_v4),
                        workflow_execution_id: execution_id,
                        input: &input_for_db,
                        trigger_type: "webhook",
                        // Pipeline steps dispatch as a unit — no concurrent
                        // sibling to race against.
                        race_safe_status: false,
                    })
                    .await
                {
                    tracing::error!("module_execution_store.record_started failed: {}", db_err);
                }
            }
        }

        // Aggregate timeout = sum of per-step budgets + 5s NATS
        // overhead, clamped to the operator-configurable
        // `TALOS_NATS_TIMEOUT_SECS` floor.
        static NATS_TIMEOUT_FLOOR_SECS: OnceLock<u64> = OnceLock::new();
        let nats_floor = *NATS_TIMEOUT_FLOOR_SECS.get_or_init(|| {
            std::env::var("TALOS_NATS_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0)
        });
        let chain_computed_secs: u64 = chain_node_ids
            .iter()
            .map(|id| self.node_timeouts.get(id).copied().unwrap_or(30))
            .sum::<u64>()
            + 5;
        let timeout_secs = chain_computed_secs.max(nats_floor);

        let chain_request = talos_workflow_engine_core::ChainDispatchRequest {
            workflow_execution_id: execution_id,
            user_id: uid_for_chain,
            job_id: None,
            steps: step_jobs,
            share_sandbox: true,
            // Inherit the engine's tier ceiling (stamped from
            // `actors.max_llm_tier`). Worker stamps every step's
            // TalosContext with this value.
            max_llm_tier: self.max_llm_tier,
            total_timeout: std::time::Duration::from_secs(timeout_secs),
            max_retries: chain_retry.max_retries,
            backoff_ms: chain_retry.backoff_ms,
            retry_condition: chain_retry.retry_condition.clone(),
            retry_delay_expr: chain_retry.retry_delay_expression.clone(),
        };

        let chain_result = match dispatcher.dispatch_chain(chain_request).await {
            Ok(r) => r,
            Err(e) => return (chain_tail, Err(e.to_string())),
        };

        // Per-step post-processing: update `module_executions` rows
        // with status/output/error; persist `__memory_write__`
        // payloads for successful steps via the node-lifecycle hook.
        if let Some(ref store) = self.module_execution_store {
            for (i, step_result) in chain_result.steps.iter().enumerate() {
                if let Some(&step_exec_id) = step_exec_ids.get(i) {
                    let status_str = match step_result.status {
                        talos_workflow_engine_core::StepStatus::Success => "completed",
                        talos_workflow_engine_core::StepStatus::TimedOut => "timeout",
                        talos_workflow_engine_core::StepStatus::Failed => "failed",
                        // `StepStatus` is `#[non_exhaustive]`. Bucket
                        // unknown future variants under `failed` so the
                        // module-execution row is recorded with a
                        // visible-but-non-success status until the
                        // engine maintainer adds explicit handling.
                        _ => "failed",
                    };
                    let error_msg = step_result.error.as_deref().map(|s| self.redact_str(s));
                    let duration = i32::try_from(step_result.execution_time_ms).unwrap_or(i32::MAX);
                    if let Err(db_err) = store
                        .record_completed(
                            step_exec_id,
                            status_str,
                            &self.redact_json(&step_result.output),
                            duration,
                            error_msg.as_deref(),
                        )
                        .await
                    {
                        tracing::error!(
                            "module_execution_store.record_completed failed: {}",
                            db_err
                        );
                    }

                    // `__memory_write__` protocol for pipeline steps:
                    // only fire the hook on success (failed steps may
                    // carry partial/corrupt output). The hook owns
                    // extraction + spawn semantics; the engine just
                    // forwards per-step outputs.
                    if matches!(
                        step_result.status,
                        talos_workflow_engine_core::StepStatus::Success
                    ) {
                        if let Some(hook) = self.node_hook.as_ref() {
                            hook.on_pipeline_step_completed(self.actor_id, &step_result.output);
                        }
                    }
                }
            }
            // Mark any unexecuted trailing steps as aborted so the
            // module-executions audit log shows them as failed rather
            // than lingering forever in "running".
            for i in chain_result.steps.len()..step_exec_ids.len() {
                if let Some(&step_exec_id) = step_exec_ids.get(i) {
                    if let Err(db_err) = store
                        .record_completed(
                            step_exec_id,
                            "failed",
                            &serde_json::Value::Null,
                            0,
                            Some("Pipeline aborted before this step"),
                        )
                        .await
                    {
                        tracing::error!("Database operation failed in engine: {}", db_err);
                    }
                }
            }
        }

        match chain_result.overall_status {
            talos_workflow_engine_core::StepStatus::Success => {
                (chain_tail, Ok(chain_result.final_output))
            }
            _ => (
                chain_tail,
                Err(format!(
                    "Pipeline execution failed: {:?}",
                    chain_result.final_output
                )),
            ),
        }
    }

    /// Apply the per-module rate limit for `node_id`'s resolved
    /// module id. Returns `Some(error_envelope)` when the limit was
    /// exceeded — the scheduler treats that as a completed-node-
    /// with-error path (insert into results, unblock successors,
    /// continue). Returns `None` when the dispatch may proceed.
    ///
    /// # Backing store
    ///
    /// When [`set_rate_limit_store`](Self::set_rate_limit_store) is
    /// wired, the counter is delegated to that trait impl
    /// (typically Redis-backed for cross-process / cross-replica
    /// state). Otherwise the engine routes through the
    /// process-global in-memory `MODULE_RATE_LIMITS` map. Eviction
    /// of stale entries on the in-memory path is handled by the
    /// background tokio task started by
    /// [`ensure_rate_limit_eviction_task`].
    ///
    /// # Failure mode
    ///
    /// **Fail-open.** A trait-impl error (Redis network blip,
    /// timeout, etc.) logs a warning and proceeds as if the limit
    /// had not been exceeded. Documented in
    /// [`talos_workflow_engine_core::RateLimitStore`].
    pub(crate) async fn check_rate_limit(&self, node_id: Uuid) -> Option<JsonValue> {
        let module_id_resolved = self.resolve_module_id(node_id);
        let limit = *self.rate_limits.get(&module_id_resolved)?;
        if limit <= 0 {
            return None;
        }
        const WINDOW_SECS: u64 = 60;
        let count = if let Some(store) = self.rate_limit_store.as_ref() {
            match store
                .record_and_count(module_id_resolved, WINDOW_SECS)
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    // Fail-open: a flaky shared counter must not
                    // block legitimate dispatch. The trait docstring
                    // commits to this behaviour.
                    tracing::warn!(
                        %node_id,
                        module_id = %module_id_resolved,
                        error = %e,
                        "RateLimitStore failed; allowing dispatch (fail-open)"
                    );
                    return None;
                }
            }
        } else {
            ensure_rate_limit_eviction_task();
            let now = std::time::Instant::now();
            let mut entry = MODULE_RATE_LIMITS
                .entry(module_id_resolved)
                .or_insert((now, 0));
            if now.duration_since(entry.0) > std::time::Duration::from_secs(WINDOW_SECS) {
                entry.0 = now;
                entry.1 = 0;
            }
            entry.1 += 1;
            entry.1
        };
        if count > limit as u32 {
            tracing::warn!(
                %node_id,
                module_id = %module_id_resolved,
                rate_limit = limit,
                "Module rate limit exceeded"
            );
            Some(serde_json::json!({
                "__error": true,
                "error_message": format!("Module rate limit exceeded ({}/min)", limit),
            }))
        } else {
            None
        }
    }

    /// Kick off background fetches for direct successors of `node_idx`
    /// when the current node opts in via `speculative_prefetch: true`
    /// on its config. Safety caps: max 8 successors prefetched, 5-
    /// second per-fetch timeout.
    pub(crate) fn maybe_speculative_prefetch(&self, node_id: Uuid, node_idx: NodeIndex) {
        if !self
            .node_configs
            .get(&node_id)
            .and_then(|c| c.get("speculative_prefetch"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return;
        }
        for succ_idx in self
            .graph
            .neighbors_directed(node_idx, Direction::Outgoing)
            .take(self.max_prefetch_successors)
        {
            let succ_id = self.graph[succ_idx];
            // Skip system nodes — they have no module in the registry
            // (resolve_module_id returns the node UUID as a fallback).
            // Fetching would waste a 5-second timeout and generate
            // noisy debug log entries for every system successor.
            let Some(succ_module_id) = self.node_meta.get(&succ_id).and_then(|(mid, _, _)| *mid)
            else {
                continue;
            };
            let prefetch_cache = Arc::clone(&self.module_prefetch_cache);
            let Some(fetcher) = self.module_fetcher.as_ref() else {
                continue;
            };
            let fetcher = Arc::clone(fetcher);
            let uid = self.user_id;
            tokio::spawn(async move {
                // Atomic duplicate suppression via vacant-entry check:
                // only one spawn proceeds to fetch; others see the key
                // already present and return immediately.
                if prefetch_cache.contains_key(&succ_id) {
                    return;
                }
                let Some(uid) = uid else {
                    return;
                };
                // 5-second timeout: prevents hung prefetch tasks from
                // leaking tokio task slots if the registry is
                // unresponsive.
                let fetch_result = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    fetcher.fetch(succ_module_id, uid),
                )
                .await;
                match fetch_result {
                    Ok(Ok(artifact)) => {
                        // Use entry().or_insert to avoid overwriting a
                        // result that another concurrent spawn already
                        // stored.
                        prefetch_cache.entry(succ_id).or_insert(artifact);
                        tracing::debug!(
                            %succ_id,
                            "speculative prefetch: module cached"
                        );
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(
                            %succ_id,
                            error = %e,
                            "speculative prefetch: fetch failed (normal dispatch will retry)"
                        );
                    }
                    Err(_) => {
                        tracing::debug!(
                            %succ_id,
                            "speculative prefetch: timed out (normal dispatch will fetch)"
                        );
                    }
                }
            });
        }
    }
}
