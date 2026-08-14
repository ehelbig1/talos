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
use crate::secrets_pipeline::extract_vault_paths;

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
        accumulated_snapshot: Option<Arc<JsonValue>>,
        execution_id: Uuid,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
    ) -> (NodeIndex, Result<JsonValue, String>) {
        let chain_tail = chain[chain.len() - 1];

        // RFC 0010 P3 (D3b): pipelines now support claim-based sealing — each
        // step's plaintext is resolved below (`build_dispatch_secrets_for`) and
        // the dispatcher collects them into ONE sealed claim for the pipeline. No
        // fail-closed guard here anymore; the flag flows through per step.
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
        // The chain head's resolved capability world, captured during the step
        // loop so the actor-context injection below can apply the same
        // world-aware `needs_memory` default the single-node path uses (a
        // pure-egress head node doesn't receive injected memory by default).
        let mut head_capability_world: Option<String> = None;
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
            // P2: route through the per-execution artifact cache so a module
            // reused across multiple pipeline steps / branches is fetched (and
            // its full wasm_bytes blob SELECTed) at most once per run. The Arc
            // is read-only here (`artifact.as_ref()` everywhere below), so the
            // cache hand-out is a refcount bump, not a blob clone.
            let (artifact, mut module_config) = match self.module_fetcher.as_ref() {
                Some(fetcher) => match self
                    .fetch_module_artifact_cached(fetcher, step_module_id, uid)
                    .await
                {
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

            // Capture the head node's capability world for the memory-injection
            // gate below (see `head_capability_world`).
            if step_node_id == chain_head_id {
                head_capability_world = artifact.as_ref().map(|a| a.capability_world.clone());
            }

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
                                "[APPROVAL_PENDING] Execution paused: module {step_node_id} requires approval for {requires_approval:?}. \
                                 Not a genuine failure — an approval request has been created; approve it, then retry. \
                                 (Dashboards/alerts can filter on the [APPROVAL_PENDING] prefix.)"
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

            // Per-node fuel precedence: node-config `max_fuel` > module default
            // > 1M fallback, then the adaptive learned ceiling as a floor,
            // clamped to 50M. Shared decision point with the single + loop
            // paths (see `resolve_node_max_fuel`).
            let module_default_fuel = artifact
                .as_ref()
                .map(|a| a.max_fuel)
                .filter(|f| *f > 0)
                .unwrap_or(1_000_000);
            let node_max_fuel = self.resolve_node_max_fuel(
                &step_node_id,
                module_config.get("max_fuel").and_then(|v| v.as_u64()),
                module_default_fuel,
            );

            // RFC 0010 P3 (D3b): resolve each step's secrets in whichever form the
            // sealing mode needs — inline WSK envelope, OR plaintext for
            // claim-based sealing (the dispatcher collects the per-step plaintext
            // into one sealed claim payload). Same `build_dispatch_secrets_for`
            // helper as the single-node + loop paths, so the flag applies
            // uniformly. L-1: AAD = execution_id binds each step's legacy AES-GCM
            // tag to this dispatch (steps share the execution_id AAD deliberately;
            // step-level granularity is enforced by the wider JobRequest HMAC).
            let step_secrets = match (self.secrets_resolver.as_ref(), &worker_shared_key) {
                (Some(resolver), Some(key)) => {
                    crate::secrets_pipeline::build_dispatch_secrets_for(
                        resolver.as_ref(),
                        self.secret_envelope.as_ref(),
                        step_node_id,
                        self.user_id,
                        &vault_paths,
                        &[],
                        key.as_bytes(),
                        self.max_llm_tier,
                        execution_id.as_bytes(),
                    )
                    .await
                }
                _ => crate::secrets_pipeline::DispatchSecrets::default(),
            };

            // Opt-in idempotency (Task 1 follow-up): resolve THIS step's
            // declared key from its merged config, STRIP the engine-only
            // `__idempotency_key__` directive so it never reaches guest code as
            // module input, and stamp the resolved key onto the step's
            // DispatchJob (the NATS adapter maps it to `PipelineStep.idempotency_key`,
            // HMAC-bound via the `:idem=` signing segment). `auto`/`true` derive
            // a STABLE `<exec_id>:<step_node_id>` key — stable across retry
            // attempts of the same dispatch (so the destination dedupes a
            // retried step) and unique per logical send per execution. Mirrors
            // the single-node path in `engine_dispatch_single`.
            let step_idempotency_key =
                talos_workflow_engine_core::reserved_keys::resolve_idempotency_key(
                    Some(&module_config),
                    &execution_id,
                    &step_node_id,
                );
            if let Some(obj) = module_config.as_object_mut() {
                obj.remove(talos_workflow_engine_core::reserved_keys::IDEMPOTENCY_KEY);
            }

            // Base per-step retry count (same precedence as before: explicit
            // node policy → method-aware default; expression-gated policies
            // fall back to 0 because the worker can't evaluate Rhai).
            let base_max_retries = {
                let step_policy = self
                    .node_meta
                    .get(&step_node_id)
                    .and_then(|(_, rp, _)| rp.clone());
                match step_policy {
                    Some(p)
                        if p.retry_condition.is_some() || p.retry_delay_expression.is_some() =>
                    {
                        tracing::debug!(
                            %step_node_id,
                            "pipeline step has an expression-gated retry policy; \
                             in-worker step retries disabled for this step \
                             (expressions are controller-side only)"
                        );
                        0
                    }
                    Some(p) => p.max_retries,
                    None => talos_workflow_engine_core::default_max_retries_for_module(
                        artifact
                            .as_ref()
                            .map(|a| a.allowed_methods.as_slice())
                            .unwrap_or(&[]),
                        artifact.as_ref().map(|a| a.capability_world.as_str()),
                    ),
                }
            };
            // When idempotency IS declared, a declared Idempotency-Key header
            // makes an otherwise-non-idempotent send step safe to retry at the
            // HTTP boundary — upgrade 0→transient only for HTTP-egress worlds,
            // never lower an explicit count, never touch a non-declaring step.
            // Same decision (unit-tested) the single-node path uses.
            let step_max_retries = talos_workflow_engine_core::effective_retries_with_idempotency(
                base_max_retries,
                artifact
                    .as_ref()
                    .map(|a| a.capability_world.as_str())
                    .unwrap_or(""),
                step_idempotency_key.is_some(),
            );

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
                // User-scoped redis URI (L-27): keyed on `uid` + `step_module_id`
                // to match `wasm:{user_id}:{module_id}`, the key the registry
                // pre-warmed under this same `uid` in the fetch above. The
                // worker strips `redis:` and GETs it verbatim.
                module_uri: artifact
                    .as_ref()
                    .and_then(|a| a.oci_url.clone())
                    .unwrap_or_else(|| {
                        talos_workflow_engine_core::scoped_wasm_redis_uri(uid, step_module_id)
                    }),
                // Embed bytes when the fetcher already resolved them,
                // matching `engine_dispatch_single.rs` and the loop
                // dispatcher in `scheduler_handlers.rs`. Skips the
                // Redis-key class of bugs (`wasm:{uid}:{id}` vs
                // `wasm:{id}`) and the prior-comment-claim-but-not-code
                // inconsistency above.
                wasm_bytes: artifact.as_ref().and_then(|a| {
                    if crate::dispatch_bytes::embeds_inline(&a.wasm_bytes) {
                        Some(a.wasm_bytes.clone())
                    } else {
                        None
                    }
                }),
                // Worker only consults the hash on a URI fetch; when
                // bytes are inline, the envelope HMAC already covers
                // them. Oversized components (interpreter toolchains)
                // route by URI too — see `dispatch_bytes`.
                expected_wasm_hash: artifact.as_ref().and_then(|a| {
                    if crate::dispatch_bytes::embeds_inline(&a.wasm_bytes) {
                        None
                    } else {
                        Some(a.content_hash.clone())
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
                encrypted_secrets_ciphertext: step_secrets.encrypted.ciphertext,
                encrypted_secrets_nonce: step_secrets.encrypted.nonce,
                // RFC 0010 P3 (D3b): per-step plaintext under claim-based sealing
                // (None/empty otherwise). The dispatcher (`dispatch_chain`)
                // collects these into ONE sealed claim payload for the pipeline.
                plaintext_secrets: step_secrets.plaintext,
                secret_paths: step_secrets.secret_paths,
                priority: 100,
                dry_run: self.dry_run,
                // Inherit the engine's tier ceiling (stamped from
                // `actors.max_llm_tier` by the controller at dispatch time).
                max_llm_tier: self.max_llm_tier,
                max_write_ceiling: self.max_write_ceiling,
                egress_scope: self.egress_scope,
                // Opt-in per-step idempotency (Task 1 follow-up): the resolved
                // key (or `None` for a non-declaring step), stamped above and
                // HMAC-bound via the `:idem=` pipeline signing segment. The
                // worker emits it as an `Idempotency-Key` header on the step's
                // mutating sends.
                idempotency_key: step_idempotency_key,
                // Per-step retry policy (2026-07-24): pipelines previously
                // hardcoded 0 here, so a chain step NEVER retried an
                // application failure — the chain-level `dispatch_with_retry`
                // only covers transport errors. Now each step carries its own
                // node policy (method-aware default when absent), executed
                // IN-WORKER by the pipeline step loop under the transient
                // classifier. `effective_retries_with_idempotency` (applied
                // above) upgrades a DECLARED-idempotent HTTP-egress send step
                // from 0→transient; a non-declaring step keeps its base count.
                // Steps whose policy carries a Rhai retry_condition /
                // retry_delay_expression fall back to 0 (the worker cannot
                // evaluate expressions).
                max_retries: step_max_retries,
                backoff_ms: self
                    .node_meta
                    .get(&step_node_id)
                    .and_then(|(_, rp, _)| rp.as_ref().map(|p| p.backoff_ms))
                    .unwrap_or(500),
                retry_condition: None,
                retry_delay_expr: None,
                // Chain-level retry events are not emitted per-step; the
                // worker logs per-attempt retries into the step's module log.
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
                    // Deep-clone the shared snapshot only here, at the single
                    // point it is materialized into the dispatched envelope.
                    obj.insert("__accumulated__".to_string(), (**acc).clone());
                }
            }
            if let Some(ref ctx) = self.actor_context {
                // Node-scoped injection keyed on the chain's head node. OFF →
                // inject as today; ON → only when the head declares
                // `needs_memory` — world-aware default (a pure-egress/send head
                // world defaults to NO memory; explicit `needs_memory: true`
                // still injects). `head_capability_world` is None only if the
                // head artifact didn't resolve, in which case we fall back to
                // the config-only default (treat as memory-consuming) — the
                // conservative choice.
                let head_needs_memory = match head_capability_world.as_deref() {
                    Some(world) => self.node_needs_memory_for_world(chain_head_id, world),
                    None => self.node_needs_memory(chain_head_id),
                };
                // Fleet-wide `ENABLE_ACTOR_CONTEXT_INJECTION` kill-switch is the
                // outermost gate (off ⇒ no injection anywhere).
                if talos_config::actor_context_injection_enabled()
                    && talos_workflow_engine_core::reserved_keys::should_inject_actor_context(
                        talos_config::smart_memory_context_enabled(),
                        head_needs_memory,
                    )
                {
                    if let Some(obj) = wrapped.as_object_mut() {
                        obj.insert("__actor_context__".to_string(), ctx.clone());
                    }
                }
            }
            // Input-freshness contracts across the chain. Unlike actor-context
            // (keyed on the head), freshness is checked for EVERY node in the
            // chain: a chain is any linear in=out=1 run, so the memory-reading
            // node is often NOT the head (the delivery pattern's
            // compose → send is exactly this shape). Keying on the head alone
            // would silently ignore a declared contract — the same silent-miss
            // class this mechanism exists to remove. Reports merge by entry
            // union; the chain fails if ANY node opted into on_stale=fail and
            // is genuinely violated.
            let mut merged_entries: Vec<JsonValue> = Vec::new();
            let mut merged_any_stale = false;
            let mut merged_verified = true;
            let mut declared = false;
            for &nid in &chain_node_ids {
                if let Some((report, must_fail)) = self.resolve_node_staleness(nid).await {
                    declared = true;
                    if must_fail {
                        let detail =
                            talos_workflow_engine_core::reserved_keys::describe_stale_entries(
                                &report,
                            );
                        return (
                            chain_tail,
                            Err(format!(
                                "input freshness contract violated (on_stale=fail): {detail}"
                            )),
                        );
                    }
                    merged_any_stale |= report
                        .get("any_stale")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    merged_verified &= report
                        .get("verified")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if let Some(entries) = report.get("entries").and_then(|e| e.as_array()) {
                        merged_entries.extend(entries.iter().cloned());
                    }
                }
            }
            if declared {
                if let Some(obj) = wrapped.as_object_mut() {
                    obj.insert(
                        "__staleness__".to_string(),
                        serde_json::json!({
                            "verified": merged_verified,
                            "any_stale": merged_any_stale,
                            "entries": merged_entries,
                        }),
                    );
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
        // `uid_for_chain` is destructured here rather than
        // `unwrap_or_else(Uuid::new_v4)`'d at the `user_id` binding below —
        // the exact twin of the `engine_dispatch_single` site fixed alongside
        // this one, and left standing when that one was cleaned up. The minted
        // fallback reads as a guaranteed `users`-FK violation; it is not (the
        // `None` arm is unreachable: `uid_for_chain` is only `None` when
        // `module_fetcher` is `None`, and in that case the step loop above
        // returns `Err` on its first iteration — the chain is never empty,
        // `chain_node_ids[0]` is indexed unconditionally at the top of this
        // function). Binding it makes the guarantee structural instead of
        // something the next reader has to re-derive, and in the impossible
        // `None` case the pre-INSERT loop is skipped (leaving `step_exec_ids`
        // empty, which every consumer below already handles via `.get(i)`)
        // rather than writing rows the FK would reject anyway.
        if let (Some(ref store), Some(chain_user_id)) =
            (&self.module_execution_store, uid_for_chain)
        {
            for (i, &actual_mid) in chain_module_ids.iter().enumerate() {
                let step_exec_id = Uuid::new_v4();
                step_exec_ids.push(step_exec_id);
                let input_for_db = if i == 0 {
                    serde_json::json!({ "input": chain_input })
                } else {
                    serde_json::json!(null)
                };
                // `module_id` MUST be the resolved MODULE id. `chain_module_ids`
                // already maps each graph node id -> module id via the engine's
                // resolver (graph node ids are SHA256-derived from the label and
                // never match a `modules` row). The prior
                // `store.resolve_module_id(step_node_id)` passed the NODE id to
                // the store's identity-fn resolver, so a node id was inserted
                // into `module_executions.module_id` — violating the FK to
                // `modules.id` and dropping per-step tracking on EVERY
                // multi-node (pipeline) execution (the single-node path was
                // unaffected; it already passes a resolved module id).
                if let Err(db_err) = store
                    .record_started(ExecutionStartedContext {
                        id: step_exec_id,
                        module_id: actual_mid,
                        user_id: chain_user_id,
                        workflow_execution_id: execution_id,
                        input: &input_for_db,
                        trigger_type: "webhook",
                        // Pipeline steps dispatch as a unit — no concurrent
                        // sibling to race against.
                        race_safe_status: false,
                        // Attribute the step's module run to the workflow's actor.
                        actor_id: self.actor_id,
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
            // `None` ⇒ the dispatcher mints the wire id
            // (`NatsNodeDispatcher::dispatch_chain`). No `module_executions`
            // row is ever created under that minted id, so it would be an
            // orphan-log id if anything routed logs by it. Nothing does: the
            // worker stamps `wasm.log.{workflow_execution_id}` for pipeline
            // steps, NOT the chain `job_id`
            // (`talos_worker_runtime::pipeline_log_execution_id`), and
            // `workflow_execution_id` above names a real `workflow_executions`
            // row. That coupling is the ONLY thing keeping this path out of
            // the #618 orphan family — a future change to which id the worker
            // stamps for a pipeline must either keep it the parent execution
            // id or start supplying a RECORDED `job_id` here.
            job_id: None,
            steps: step_jobs,
            share_sandbox: true,
            // Inherit the engine's tier ceiling (stamped from
            // `actors.max_llm_tier`). Worker stamps every step's
            // TalosContext with this value.
            max_llm_tier: self.max_llm_tier,
            max_write_ceiling: self.max_write_ceiling,
            egress_scope: self.egress_scope,
            total_timeout: std::time::Duration::from_secs(timeout_secs),
            max_retries: chain_retry.max_retries,
            backoff_ms: chain_retry.backoff_ms,
            retry_condition: chain_retry.retry_condition.clone(),
            retry_delay_expr: chain_retry.retry_delay_expression.clone(),
        };

        let chain_result = match dispatcher.dispatch_chain(chain_request).await {
            Ok(r) => r,
            Err(e) => {
                // A FRESH INSTANCE OF THE CLASS THIS CHANGE FIXES, found in
                // review of the change itself. This arm used to be a bare
                // `return`, sitting BELOW the per-step `record_started` loop —
                // so on a chain-level dispatch failure every one of the N step
                // rows was abandoned in `'running'` and swept 30 minutes later
                // to `'timeout'`/`error_type='stuck'`. Exactly the single-node
                // defect, in the file that was edited to fix it.
                //
                // And this is the LIKELY arm, not an exotic one:
                // `dispatch_with_retry` returns `"Job execution timed out"`
                // against the AGGREGATE chain deadline, which is the SUM of the
                // per-step budgets — so the longer the pipeline, the more rows
                // one timeout strands.
                //
                // Same chokepoint, same classifier as the single-node path: the
                // dispatcher's own timeout sentinel records `'timeout'`,
                // anything else `'failed'`.
                let message = e.to_string();
                let status =
                    crate::engine_dispatch_single::classify_dispatch_failure_status(&message);
                for &step_exec_id in &step_exec_ids {
                    // `duration_ms: 0`, matching the aborted-trailing-step loop
                    // below. We know the chain's wall time but NOT any step's,
                    // and stamping the whole chain duration onto each of N rows
                    // would fabricate N× the elapsed work. The value is moot in
                    // practice — the `calculate_module_execution_duration`
                    // BEFORE UPDATE trigger overwrites it with
                    // `completed_at - started_at` on this, the row's first
                    // terminal write — but 0 is the honest thing to pass.
                    self.finalize_module_execution_row(
                        step_exec_id,
                        status,
                        &serde_json::Value::Null,
                        0,
                        Some(&message),
                    )
                    .await;
                }
                return (chain_tail, Err(message));
            }
        };

        // Per-step post-processing: update `module_executions` rows
        // with status/output/error; persist `__memory_write__`
        // payloads for successful steps via the node-lifecycle hook.
        // The `is_some()` gate is redundant now that
        // `finalize_module_execution_row` returns early without a store, but
        // it still short-circuits the per-step loop (and the memory-write
        // hook is nested inside it) — keep the shape, drop the unused bind.
        if self.module_execution_store.is_some() {
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
                    // Shared chokepoint (`engine_dispatch_single.rs`): owns
                    // the redact-record-log shape for every engine path that
                    // closes a `module_executions` row.
                    self.finalize_module_execution_row(
                        step_exec_id,
                        status_str,
                        &step_result.output,
                        duration,
                        error_msg.as_deref(),
                    )
                    .await;

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
                    self.finalize_module_execution_row(
                        step_exec_id,
                        "failed",
                        &serde_json::Value::Null,
                        0,
                        Some("Pipeline aborted before this step"),
                    )
                    .await;
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

#[cfg(test)]
mod pipeline_ledger_finalize_tests {
    //! Guard for the 2026-08-13 finding: `run_pipeline_chain_dispatch`'s
    //! `dispatch_chain` ERROR arm was a bare `return`, sitting below the loop
    //! that `record_started`s one `module_executions` row per step. Every one
    //! of those N rows was therefore abandoned in `'running'` and swept 30
    //! minutes later to `'timeout'` / `error_type='stuck'` — the same defect
    //! the single-node path was fixed for, in the same commit, one file over.
    //!
    //! These drive the REAL `run_pipeline_chain_dispatch` through the
    //! in-memory adapters, and the pre-fix failure was DEMONSTRATED, not
    //! asserted: with only the `dispatch_chain` Err arm reverted to its bare
    //! `return` (file copied in and back out, never `git checkout` — the tree
    //! is uncommitted), both tests FAIL with `left: 0, right: 2` terminal
    //! calls, rc 101. The restore diffs clean.
    //!
    //! What they do NOT prove: that the Postgres UPDATE lands — the capture
    //! store records the call, it does not write a row.
    //!
    //! ON REACHABILITY, WITH THE EVIDENCE GRADED. The bug is LATENT rather
    //! than live: the chain gate in `engine.rs` was `is_fresh_run =
    //! initial_results.is_empty()`, and a trigger has always seeded a
    //! synthetic `__trigger__` node into `initial_results`, so `chains` is
    //! empty on every trigger path and `run_pipeline_chain_dispatch` is never
    //! called. That was a code argument when this was written, and two obvious
    //! DB cross-checks do NOT settle it — all three engine paths stamp
    //! `trigger_type: "webhook"` on the row, so the column cannot tell them
    //! apart, and the worker's container logs only cover the current process
    //! lifetime. Fixed regardless: reachability is a separate question from
    //! correctness, and it can change.
    //!
    //! 2026-08-13 UPDATE — the reachability question was taken up separately
    //! and the gate is now an explicit `ChainDispatch` parameter threaded from
    //! each entry point (`engine.rs`), rather than a property inferred from a
    //! `HashMap::is_empty()` call. Every production entry point passes
    //! `Disabled`, so this file remains unreached on the deployed platform,
    //! and `tests/chain_dispatch_gate.rs` pins that through the real entry
    //! point. Turning it on is NOT a one-line flip — see `ChainDispatch`'s
    //! docs: this file has no `skip_condition` HANDLING whatsoever, and the
    //! workflows that use `skip_condition` today are mostly, but not entirely,
    //! SEND nodes (5 workflows / 7 nodes; two are a sub-workflow node and a
    //! Gmail label mutation — see `ChainDispatch` for the census).
    //!
    //! The instruction here used to be "(grep it)", which now falsifies itself:
    //! `grep -c skip_condition` on this file returns 2, and both hits are
    //! inside this very sentence. A claim whose stated verification method
    //! disproves it is worse than no claim — the property to check is that no
    //! CODE path in this file consults a skip condition, which a grep for the
    //! identifier cannot distinguish from prose about it.

    use std::sync::Arc;

    use async_trait::async_trait;
    use petgraph::graph::NodeIndex;
    use serde_json::json;
    use talos_workflow_engine_core::{
        BoxError, ChainDispatchRequest, ChainDispatchResult, DispatchJob, DispatchResult,
        NodeDispatcher, WasmModuleArtifact,
    };
    use talos_workflow_engine_test_utils::capture::{
        CaptureModuleExecutionStore, ExecutionStoreCall,
    };
    use talos_workflow_engine_test_utils::memory::InMemoryModuleFetcher;
    use uuid::Uuid;

    use crate::engine::ParallelWorkflowEngine;

    /// A dispatcher whose `dispatch_chain` fails at the CHAIN level — the
    /// shape `ScriptedDispatcher` cannot produce, because its default
    /// `dispatch_chain` body (`dispatch_chain_sequential`) folds per-step
    /// errors into a `ChainDispatchResult` and never returns `Err`.
    struct ChainErrorDispatcher {
        message: String,
    }

    #[async_trait]
    impl NodeDispatcher for ChainErrorDispatcher {
        async fn dispatch(&self, _job: DispatchJob) -> Result<DispatchResult, BoxError> {
            Err("pipeline test: per-step dispatch should not be reached".into())
        }

        async fn dispatch_chain(
            &self,
            _request: ChainDispatchRequest,
        ) -> Result<ChainDispatchResult, BoxError> {
            Err(self.message.clone().into())
        }
    }

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

    /// Two-step chain, both steps backed by real artifacts so the pre-dispatch
    /// step loop runs to completion and both `record_started` rows are opened.
    async fn dispatch_chain_once(
        error_message: &str,
    ) -> (
        Arc<CaptureModuleExecutionStore>,
        Result<serde_json::Value, String>,
    ) {
        let store = Arc::new(CaptureModuleExecutionStore::new());
        let mod_a = Uuid::new_v4();
        let mod_b = Uuid::new_v4();
        let node_a = Uuid::new_v4();
        let node_b = Uuid::new_v4();

        let mut engine = ParallelWorkflowEngine::new();
        engine.set_user_id(Uuid::new_v4());
        // Bare `set_actor_id` needs no opt-out: lint check 29 excludes
        // `talos-workflow-engine/**` wholesale.
        engine.set_actor_id(Uuid::new_v4());
        engine.set_module_execution_store(store.clone());
        engine.set_module_fetcher(Arc::new(
            InMemoryModuleFetcher::new()
                .with_module(mod_a, stub_artifact(mod_a))
                .with_module(mod_b, stub_artifact(mod_b)),
        ));
        engine.add_node(node_a, Some(mod_a), None, None);
        engine.add_node(node_b, Some(mod_b), None, None);

        let chain: Vec<NodeIndex> = vec![
            *engine.node_map.get(&node_a).expect("node a in graph"),
            *engine.node_map.get(&node_b).expect("node b in graph"),
        ];

        let dispatcher: Arc<dyn NodeDispatcher> = Arc::new(ChainErrorDispatcher {
            message: error_message.to_string(),
        });

        let out = engine
            .run_pipeline_chain_dispatch(
                chain,
                json!({ "seed": 1 }),
                None,
                Uuid::new_v4(),
                dispatcher,
                None,
            )
            .await
            .1;
        (store, out)
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

    /// THE regression. EVERY step row opened before the chain dispatch is
    /// closed when the chain dispatch itself fails — not "at least one", and
    /// not the rows of some other chain.
    #[tokio::test]
    async fn a_chain_dispatch_error_finalizes_every_step_row_it_opened() {
        let (store, out) = dispatch_chain_once("transport exploded").await;
        assert!(out.is_err(), "the chain error propagates to the caller");

        let opened = started_ids(&store);
        assert_eq!(opened.len(), 2, "one start row per pipeline step");
        let mut closed = terminal_calls(&store);
        assert_eq!(
            closed.len(),
            2,
            "every step row must be finalized — pre-fix this was 0 and all N \
             rows were swept to 'timeout'/'stuck' 30 minutes later"
        );
        closed.sort_by_key(|(id, _)| *id);
        let mut expected = opened;
        expected.sort();
        let closed_ids: Vec<Uuid> = closed.iter().map(|(id, _)| *id).collect();
        assert_eq!(closed_ids, expected, "finalized exactly the rows it opened");
        for (_, status) in &closed {
            assert_eq!(status, "failed", "a non-timeout chain error is 'failed'");
        }
    }

    /// The chain deadline is the SUM of the per-step budgets, so the
    /// dispatcher's timeout sentinel is the arm this path hits most. It must
    /// record `'timeout'`, using the same narrow classifier as the single-node
    /// path — not a substring match on the module's own error text.
    #[tokio::test]
    async fn a_chain_timeout_records_timeout_on_every_step_row() {
        let (store, out) =
            dispatch_chain_once("Job dispatch failed after 1 attempts: Job execution timed out")
                .await;
        assert!(out.is_err());

        let closed = terminal_calls(&store);
        assert_eq!(closed.len(), 2);
        for (_, status) in &closed {
            assert_eq!(status, "timeout");
        }
    }
}
