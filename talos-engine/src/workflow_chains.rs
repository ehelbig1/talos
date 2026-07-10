//! Shared workflow chaining logic for all trigger types.
//!
//! When any trigger fires (webhook, scheduled job, manual run), downstream
//! nodes in the same workflow are executed in-process via
//! [`ParallelWorkflowEngine::run_with_seed`].  The trigger module's output is
//! pre-seeded so that downstream nodes receive it as their `input`.
//!
//! Call [`run_workflow_chains`] from any trigger handler to automatically
//! extend execution to linked workflow nodes.

use futures::stream::{self, StreamExt};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use talos_registry::ModuleRegistry;
use talos_secrets_manager::SecretsManager;
use talos_workflow_engine_core::{EdgeLogic, RetryPolicy, WorkerSharedKey};
use uuid::Uuid;

// The engine-construction helper that used to live here moved onto
// `ParallelWorkflowEngine::from_graph_json` so the engine doesn't
// depend on this module (breaking the pre-extraction circular dep).
// `run_single_workflow_chain` below re-inlines the node-mapping it
// needs for RF id → module id rather than routing through the engine
// constructor, because the trigger-chain path (a) does not need the
// full engine's policy adapters and (b) has to inspect `rf_to_module`
// mapping after the fact.

/// Find all workflows that contain `trigger_module_id` and execute their
/// downstream nodes in-process, with `event_data` pre-seeded as the trigger
/// module's output.
///
/// `trigger_context_id` is an opaque identifier used only for log messages
/// (e.g., a webhook channel UUID or a scheduled job ID).
///
/// This function is best-effort — errors are logged as warnings and do not
/// propagate to the caller.
pub async fn run_workflow_chains(
    nats_client: Arc<async_nats::Client>,
    secrets_manager: Arc<SecretsManager>,
    db_pool: &sqlx::Pool<sqlx::Postgres>,
    worker_shared_key: Option<WorkerSharedKey>,
    redis_client: Option<Arc<redis::Client>>,
    worker_manager: Option<Arc<talos_worker_fleet::WorkerManager>>,
    module_execution_service: Option<Arc<talos_module_executions::ModuleExecutionService>>,
    trigger_module_id: Uuid,
    user_id: Uuid,
    event_data: Value,
    trigger_context_id: Uuid,
    trigger_execution_id: Uuid,
    trigger_error: Option<String>,
) -> anyhow::Result<()> {
    let module_id_str = trigger_module_id.to_string();
    // Quick text search to avoid loading every workflow for the user.
    // Since UUIDs are unique the LIKE hit rate of false-positives is negligible.
    let search = format!("%{}%", module_id_str);

    // M-10: read `actor_id` so the chain dispatch can preserve the
    //       workflow's tier-1 enforcement and `__memory_write__`
    //       capability. Without it the chain ran as Tier-2 anonymous,
    //       silently bypassing the workflow author's intent.
    // M-12: cap the matched-workflow set to bound trigger amplification.
    //       A user with thousands of workflows referencing the trigger
    //       module would otherwise serial-dispatch all of them per
    //       trigger fire. `TALOS_CHAIN_MAX_WORKFLOWS` lets operators
    //       tune the cap; default 50.
    let chain_cap: i64 = std::env::var("TALOS_CHAIN_MAX_WORKFLOWS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(50);

    let workflows = match sqlx::query_as::<_, (Uuid, String, Option<Uuid>)>(
        "SELECT id, graph_json, actor_id \
         FROM workflows \
         WHERE user_id = $1 AND graph_json LIKE $2 \
         ORDER BY updated_at DESC \
         LIMIT $3",
    )
    .bind(user_id)
    .bind(&search)
    .bind(chain_cap + 1) // +1 so we can detect cap-hit without a second query
    .fetch_all(db_pool)
    .await
    {
        Ok(ws) => ws,
        Err(e) => {
            tracing::warn!(
                "run_workflow_chains: failed to query workflows for module {}: {}",
                trigger_module_id,
                e
            );
            return Ok(());
        }
    };

    if workflows.is_empty() {
        tracing::debug!(
            "run_workflow_chains: no workflows found for module {} — single-node execution only",
            trigger_module_id
        );
        return Ok(());
    }

    let cap_hit = workflows.len() as i64 > chain_cap;
    let workflows: Vec<_> = workflows.into_iter().take(chain_cap as usize).collect();
    if cap_hit {
        tracing::warn!(
            target: "talos_engine",
            event_kind = "chain_explosion_capped",
            user_id = %user_id,
            trigger_module_id = %trigger_module_id,
            chain_cap,
            "run_workflow_chains: matched > {chain_cap} workflows for one trigger; \
             dispatching the {chain_cap} most-recently-updated. Set TALOS_CHAIN_MAX_WORKFLOWS \
             to adjust the cap, or re-scope the trigger module so it isn't referenced \
             by so many workflows."
        );
    }

    // L-31: construct the ActorRepository ONCE per fan-out batch instead
    // of per workflow inside `run_single_workflow_chain`. Cheap (just
    // wraps a pool clone), but avoids the per-iteration Arc allocation
    // and any future repo-internal cache thrash.
    let actor_repo = Arc::new(talos_actor_repository::ActorRepository::new(
        db_pool.clone(),
    ));

    // M-12 (parallelisation): run chains via `buffer_unordered(N)` so a
    // single slow chain doesn't block every later chain. Combined with
    // the LIMIT cap above, total parallelism is bounded by both the
    // matched-workflow count AND the concurrency cap. Push-notification
    // handlers (Gmail 10s, GCal 30s) can't wedge on a long tail of
    // serial dispatches — total wall-clock is ~slowest_chain_secs
    // instead of sum_of_chain_secs. `TALOS_CHAIN_CONCURRENCY` lets
    // operators tune; default 8.
    let chain_concurrency: usize = std::env::var("TALOS_CHAIN_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(8);

    stream::iter(workflows)
        .for_each_concurrent(
            chain_concurrency,
            |(workflow_id, graph_json, workflow_actor_id)| {
                let nats_client = nats_client.clone();
                let secrets_manager = secrets_manager.clone();
                let worker_shared_key = worker_shared_key.clone();
                let redis_client = redis_client.clone();
                let worker_manager = worker_manager.clone();
                let module_execution_service = module_execution_service.clone();
                let actor_repo = actor_repo.clone();
                let event_data = event_data.clone();
                let trigger_error = trigger_error.clone();
                async move {
                    if let Err(e) = run_single_workflow_chain(
                        nats_client,
                        secrets_manager,
                        db_pool,
                        worker_shared_key,
                        redis_client,
                        worker_manager,
                        module_execution_service,
                        actor_repo,
                        workflow_id,
                        workflow_actor_id,
                        &graph_json,
                        trigger_module_id,
                        user_id,
                        event_data,
                        trigger_context_id,
                        trigger_execution_id,
                        trigger_error,
                    )
                    .await
                    {
                        tracing::warn!(
                            "run_workflow_chains: workflow {} chain failed: {}",
                            workflow_id,
                            e
                        );
                    }
                }
            },
        )
        .await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_single_workflow_chain(
    nats_client: Arc<async_nats::Client>,
    secrets_manager: Arc<SecretsManager>,
    db_pool: &sqlx::Pool<sqlx::Postgres>,
    worker_shared_key: Option<WorkerSharedKey>,
    redis_client: Option<Arc<redis::Client>>,
    _worker_manager: Option<Arc<talos_worker_fleet::WorkerManager>>,
    _module_execution_service: Option<Arc<talos_module_executions::ModuleExecutionService>>,
    // L-31: shared `ActorRepository` constructed once per fan-out batch
    // by the caller; reuse across every workflow in the batch.
    actor_repo: Arc<talos_actor_repository::ActorRepository>,
    workflow_id: Uuid,
    // M-10: workflow's owning actor (NULL for anonymous workflows).
    // Carried through so the chained engine inherits Tier-1 LLM
    // enforcement and `__memory_write__` capability via
    // `EngineOpts::with_effective_actor`.
    workflow_actor_id: Option<Uuid>,
    graph_json: &str,
    trigger_module_id: Uuid,
    user_id: Uuid,
    event_data: Value,
    trigger_context_id: Uuid,
    trigger_execution_id: Uuid,
    trigger_error: Option<String>,
) -> Result<(), String> {
    // MCP-708 (2026-05-13): upgraded from MCP-555's budget-only
    // `check_execution_allowed` to the full
    // `authorize_workflow_trigger` gate (status + budget + capability-
    // ceiling re-verification against the stored graph). Same
    // dispatch-path-authorization sweep as MCP-707 for retry/replay —
    // budget-only let an operator-downgraded actor ceiling drift open
    // across chain dispatch.
    //
    // Pre-fix bypass scenario: actor A has `max_capability_world =
    // agent-node` at T0; user builds workflow W that references trigger
    // module M and uses agent-node modules. Operator at T1 downgrades A
    // to `http-node`. At T2 webhook fires M; `run_workflow_chains`
    // finds W → dispatches → `check_execution_allowed(A)` passes (budget
    // OK) → engine runs W's agent-node modules against the now-
    // http-node-ceilinged A. Chain dispatch is a particularly bad
    // surface for this class because it's webhook-/scheduler-driven
    // fan-out — one trigger amplifies into N chain runs, multiplying
    // the bypass.
    //
    // Skip-with-warn semantics preserved per-rejection-class so
    // operators can still distinguish "dropped by budget" from
    // "dropped by ceiling drift".
    //
    // Phase D2 parity with `trigger.rs` (2026-07-10): the gate runs
    // UNCONDITIONALLY and its resolved actor is captured for the engine
    // binding below. Pre-fix, unbound chains skipped the gate AND built
    // the engine with `with_effective_actor(None, None)` — running at
    // the engine's fail-safe Tier-1 default (local-egress-only: every
    // external HTTP call died as `networkerror`) while a manual trigger
    // of the same workflow resolved the user's default actor (Tier-2).
    // The gate's Phase D1 fallback (`get_or_create_default_actor`) is
    // the single source of truth for "who does an unbound workflow run
    // as" — authorization and runtime tier now use the same answer.
    // Deny-arm log context: for an unbound chain the actor being denied is
    // the gate's internally-resolved user-default actor, whose id the error
    // variants don't carry — `actor_id: None` alone is unactionable. This
    // field plus `user_id` makes the denied principal recoverable.
    let denied_actor_source = if workflow_actor_id.is_some() {
        "workflow-bound"
    } else {
        "user-default-actor"
    };
    let effective_actor_id: Option<Uuid> = {
        let workflow_repo_for_auth =
            talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
        match talos_workflow_authorization::authorize_workflow_trigger(
            &workflow_repo_for_auth,
            &actor_repo,
            db_pool,
            workflow_actor_id,
            user_id,
            graph_json,
        )
        .await
        {
            Ok(talos_workflow_authorization::TriggerAuthorization::Authorized { actor_id }) => {
                Some(actor_id)
            }
            // Phase D1 no longer returns Unbound, but match exhaustively;
            // if it ever surfaces, fall back to the workflow's own actor
            // (the engine's Tier-1 default remains the fail-safe).
            Ok(talos_workflow_authorization::TriggerAuthorization::Unbound) => workflow_actor_id,
            Err(talos_workflow_authorization::TriggerAuthError::ActorArchived)
            | Err(talos_workflow_authorization::TriggerAuthError::ActorTerminated)
            | Err(talos_workflow_authorization::TriggerAuthError::ActorNotFoundOrInactive) => {
                tracing::warn!(
                    target: "talos_engine",
                    event_kind = "chain_dispatch_denied_actor_state",
                    workflow_id = %workflow_id,
                    actor_id = ?workflow_actor_id,
                    %user_id,
                    denied_actor_source,
                    trigger_module_id = %trigger_module_id,
                    trigger_context_id = %trigger_context_id,
                    "MCP-708: chained workflow denied — actor not in a runnable state"
                );
                return Ok(());
            }
            Err(talos_workflow_authorization::TriggerAuthError::ExecutionDenied(reason)) => {
                tracing::warn!(
                    target: "talos_engine",
                    event_kind = "chain_dispatch_denied_by_budget",
                    workflow_id = %workflow_id,
                    actor_id = ?workflow_actor_id,
                    %user_id,
                    denied_actor_source,
                    trigger_module_id = %trigger_module_id,
                    trigger_context_id = %trigger_context_id,
                    reason = %reason,
                    "MCP-708: chained workflow denied by actor budget/status gate — skipping dispatch"
                );
                return Ok(());
            }
            Err(talos_workflow_authorization::TriggerAuthError::CapabilityCeilingViolation {
                module_id,
                module_world,
                max_world,
                ..
            }) => {
                tracing::warn!(
                    target: "talos_engine",
                    event_kind = "chain_dispatch_denied_capability_ceiling",
                    workflow_id = %workflow_id,
                    actor_id = ?workflow_actor_id,
                    %user_id,
                    denied_actor_source,
                    trigger_module_id = %trigger_module_id,
                    trigger_context_id = %trigger_context_id,
                    %module_id,
                    %module_world,
                    %max_world,
                    "MCP-708: chained workflow denied — node exceeds actor capability ceiling \
                     (drift since original create; downgrade actor ceiling or remove the node)"
                );
                return Ok(());
            }
            Err(talos_workflow_authorization::TriggerAuthError::Database(e)) => {
                // Fail-CLOSED on DB error. Same contract as the
                // MCP-565 webhook path: a transient lookup failure
                // must not let a downgraded ceiling slip through.
                tracing::warn!(
                    target: "talos_engine",
                    event_kind = "chain_dispatch_denied_db_error",
                    workflow_id = %workflow_id,
                    actor_id = ?workflow_actor_id,
                    %user_id,
                    denied_actor_source,
                    error = %e,
                    "MCP-708: chained workflow denied — auth-gate DB error (fail-closed)"
                );
                return Ok(());
            }
        }
    };

    let graph: Value =
        serde_json::from_str(graph_json).map_err(|e| format!("Invalid graph_json: {}", e))?;

    let empty_vec = vec![];
    let nodes = graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .unwrap_or(&empty_vec);

    // Build React Flow node ID → module UUID mapping.
    let mut rf_to_module: HashMap<String, Uuid> = HashMap::new();
    let registry = Arc::new(ModuleRegistry::new(db_pool.clone(), redis_client.clone()));
    // Build via the canonical EngineBuilder. `for_skip_load` because the
    // chain runner assembles the graph programmatically below via
    // engine.add_node + engine.add_edge — load_graph_from_json is never
    // called. Anonymous binding (no actor): chain runs are conceptually
    // initiated by the trigger MODULE, not by an end-user actor; the
    // original execution that ran the trigger already had its actor
    // stamped. The builder's set_workflow_id call (vs. pre-PR-8 bare
    // engine) is a small upside — chain executions now bucket
    // analytics rollups by workflow_id instead of execution_id.
    // M-10: bind the workflow's actor (if any) to the chained engine so
    // tier-1 LLM enforcement and `__memory_write__` capability persist
    // across webhook/scheduled-trigger chain dispatch. Pre-fix, chains
    // ran with `actor_id = None` regardless of `workflows.actor_id` —
    // silently downgrading to Tier-2 and dropping memory writes.
    // Phase D2: prefer the gate-resolved actor (default-actor fallback
    // included) so unbound chains run at the default actor's tier
    // instead of the engine's unbound Tier-1 fail-safe.
    let opts = crate::builder::EngineOpts::for_skip_load(workflow_id)
        .with_effective_actor(effective_actor_id, workflow_actor_id);
    // MCP-682 (2026-05-13): retain a SecretsManager handle for the
    // post-run persistence step. Pre-fix the chain dispatch wrote
    // `output_data = $1` via raw SQL — bypassing Phase A encryption.
    // On encryption-enabled deployments the chain output landed in the
    // plaintext column while every other writer (scheduler, MCP
    // dispatch, ActorRepository::complete_execution) wrote to
    // `output_data_enc`. Route through the encryption-aware
    // `WorkflowRepository::mark_execution_completed` so the chain
    // matches the other three completion paths.
    let secrets_manager_for_persist = secrets_manager.clone();
    let mut engine =
        match crate::builder::for_workflow(registry, secrets_manager, actor_repo, user_id, opts)
            .await
        {
            Ok(e) => e,
            Err(crate::builder::BuildError::GraphLoad(engine_err)) => {
                // Defensive: GraphSource::SkipLoad never fires this branch today.
                return Err(format!("engine build failed: {}", engine_err));
            }
        };
    let mut has_trigger = false;
    let mut has_downstream = false;

    for node in nodes {
        let rf_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("");
        // Module UUID may be stored under "type" (save v1) or "data.moduleId" (save v2).
        let module_id_str = node
            .get("type")
            .and_then(|v| v.as_str())
            .filter(|s| Uuid::parse_str(s).is_ok()) // skip non-UUID "type" values like "talosNode"
            .or_else(|| {
                node.get("data")
                    .and_then(|d| d.get("moduleId"))
                    .and_then(|v| v.as_str())
            });
        if let Some(module_id_str) = module_id_str {
            if let Ok(module_id) = Uuid::parse_str(module_id_str) {
                tracing::debug!(
                    rf_id,
                    module_id = %module_id,
                    "workflow_chains: mapped node"
                );
                rf_to_module.insert(rf_id.to_string(), module_id);
                let retry_policy = {
                    // MCP-814 (2026-05-14): mirror the sibling
                    // `talos-workflow-engine::graph_parser::read_node_retry_policy_with_actor_cap`
                    // cap on unbudgeted (actor-less) chain dispatch.
                    // Pre-fix this reimplemented retry-policy reader
                    // accepted any `retry_count` value verbatim — a
                    // workflow with `retry_count: 999999` (whether
                    // operator typo or LLM-generated malformed JSON)
                    // would loop ~1M times per node, saturating worker
                    // fuel before the actor budget gate could fire.
                    // The cap only applies when this chain has no
                    // actor binding (`workflow_actor_id.is_none()`);
                    // actor-bound chains rely on the per-actor budget
                    // ceiling to bound retry cost at a higher layer,
                    // matching the sibling helper's policy.
                    //
                    // Helper is `pub(crate)` in the sibling repo so it
                    // can't be imported here; inlining the constant
                    // matches the cross-repo convention until the
                    // helper is promoted to `pub`.
                    const MAX_RETRIES_UNBUDGETED: u32 = 3;

                    // MCP-1174 (2026-05-17): absolute ceiling on retry
                    // count even when an owning actor is present.
                    // Pre-fix the actor-budgeted path applied no upper
                    // cap — `retry_count: 4_000_000_000` (close to
                    // u32::MAX from MCP-962's saturation) was accepted
                    // verbatim. Combined with MCP-1173's
                    // retry_backoff_ms ≤ 1 hour cap, the worst-case
                    // workflow stall is ~450,000 years; but if
                    // `retry_backoff_ms = 0` is configured (no
                    // floor-check), the engine thrashes through retries
                    // at ~1000/sec, with each iteration costing one
                    // DB UPDATE + one audit-log row. 1000 is generous
                    // for legitimate exponential-backoff schemes
                    // (10^10 attempts at 100ms each = ~11 days, too
                    // long for any sane workflow) — past this the
                    // operator should redesign the workflow rather
                    // than crank a counter. Same family as MCP-1173,
                    // MCP-962, MCP-960/961.
                    const MAX_RETRIES_BUDGETED: u32 = 1000;

                    // MCP-962 (2026-05-15): saturate u64 → u32 instead
                    // of wrapping. Pre-fix `v as u32` on `retry_count:
                    // 5_000_000_000` wrapped to ~705M, asking the
                    // engine to retry 705 million times. Saturating
                    // at u32::MAX caps the worst case to the
                    // already-cooked retry budget (still bounded by
                    // MAX_RETRIES_UNBUDGETED downstream when no
                    // budget is set). Same family as MCP-960/961.
                    let retry_count = node
                        .get("retry_count")
                        .or_else(|| node.get("data").and_then(|d| d.get("retry_count")))
                        .and_then(|v| v.as_u64())
                        .map(|v| u32::try_from(v).unwrap_or(u32::MAX));
                    // MCP-1173 (2026-05-17): cap retry_backoff_ms at 1
                    // hour. Pre-fix the value was read with no upper
                    // bound — a misconfigured node could set
                    // `retry_backoff_ms: 999_999_999_999` (~31 years)
                    // which the retry executor would sleep on between
                    // attempts. Realistic operator values: 100 ms to
                    // a few minutes; legitimate exponential-backoff
                    // ceilings don't exceed 1 hour per attempt. Same
                    // family as MCP-962 (retry_count saturation) and
                    // MCP-960/961 (signed/unsigned cast guards). Cap
                    // at u64-clamp via `.min()` so the saturation
                    // produces a finite, operator-recognisable
                    // worst-case sleep instead of "the workflow froze
                    // forever".
                    //
                    // MCP-1175 (2026-05-17): floor at MIN_RETRY_BACKOFF_MS.
                    // `retry_backoff_ms: 0` (or missing-then-floored)
                    // combined with MCP-1174's MAX_RETRIES_BUDGETED=1000
                    // produces a tight-loop retry path: ~1000 DB UPDATEs
                    // (mark_execution_running) + 1000 audit-log INSERTs
                    // (execution_events) per execution within ~1 second.
                    // Sustained for a misconfigured workflow this hits
                    // the controller's connection pool and the audit-log
                    // table's write rate. 50 ms is below any sane
                    // exponential-backoff floor for an external service
                    // (typical: 100 ms - 1 s) and above the threshold
                    // where the retry path becomes DB-write-bound. Same
                    // floor-cap-on-tight-loop class as MCP-663
                    // (MCP_TOKEN_REVALIDATION_INTERVAL_SECS positive
                    // floor) and the rate-limit-window busy-loop class.
                    const MAX_RETRY_BACKOFF_MS: u64 = 60 * 60 * 1000; // 1 hour
                    const MIN_RETRY_BACKOFF_MS: u64 = 50;
                    let retry_backoff = node
                        .get("retry_backoff_ms")
                        .or_else(|| node.get("data").and_then(|d| d.get("retry_backoff_ms")))
                        .and_then(|v| v.as_u64())
                        .map(|v| v.clamp(MIN_RETRY_BACKOFF_MS, MAX_RETRY_BACKOFF_MS));
                    let retry_condition = node
                        .get("retry_condition")
                        .or_else(|| node.get("data").and_then(|d| d.get("retry_condition")))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let retry_delay_expression = node
                        .get("retry_delay_expression")
                        .or_else(|| {
                            node.get("data")
                                .and_then(|d| d.get("retry_delay_expression"))
                        })
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let has_any = retry_count.is_some()
                        || retry_backoff.is_some()
                        || retry_condition.is_some()
                        || retry_delay_expression.is_some();
                    if has_any {
                        let mut max_retries = retry_count.unwrap_or(2);
                        if workflow_actor_id.is_none() {
                            max_retries = max_retries.min(MAX_RETRIES_UNBUDGETED);
                        } else {
                            // MCP-1174: even with an owning actor, cap
                            // the absolute count to prevent the
                            // 4-billion-retry foot-gun the MCP-962
                            // saturation alone left exposed.
                            max_retries = max_retries.min(MAX_RETRIES_BUDGETED);
                        }
                        Some(RetryPolicy {
                            max_retries,
                            backoff_ms: retry_backoff.unwrap_or(500),
                            retry_condition,
                            retry_delay_expression,
                        })
                    } else {
                        None
                    }
                };
                engine.add_node(module_id, None, retry_policy, None);
                if module_id == trigger_module_id {
                    has_trigger = true;
                } else {
                    has_downstream = true;
                }
            }
        }
    }

    tracing::debug!(
        has_trigger,
        has_downstream,
        nodes_mapped = rf_to_module.len(),
        "workflow_chains: node mapping complete"
    );

    if !has_trigger {
        // Workflow contains the module but has no other nodes connected — nothing to chain.
        return Ok(());
    }

    // Add directed edges between nodes.
    let empty_edges = vec![];
    let edges = graph
        .get("edges")
        .and_then(|e| e.as_array())
        .unwrap_or(&empty_edges);

    let mut edges_added = 0usize;
    for edge in edges {
        let src_rf = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let tgt_rf = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
        tracing::debug!(src_rf, tgt_rf, "workflow_chains: resolving edge");
        if let (Some(&src), Some(&tgt)) = (rf_to_module.get(src_rf), rf_to_module.get(tgt_rf)) {
            tracing::debug!(src = %src, tgt = %tgt, "workflow_chains: edge wired");
            let _ = engine.add_edge(
                src,
                tgt,
                EdgeLogic {
                    source_handle: "output".to_string(),
                    target_handle: "input".to_string(),
                    mapping: None,
                    condition: None,
                    edge_type: Default::default(),
                },
            );
            edges_added += 1;
        } else {
            tracing::warn!(
                src_rf,
                tgt_rf,
                src_found = rf_to_module.contains_key(src_rf),
                tgt_found = rf_to_module.contains_key(tgt_rf),
                "workflow_chains: edge source/target not found in node map — edge skipped"
            );
        }
    }
    tracing::debug!(edges_added, "workflow_chains: edge wiring complete");

    // Pre-seed the trigger module's output so downstream nodes receive the event data.
    let seed = serde_json::json!({
        "trigger_module_id": trigger_module_id.to_string(),
        "trigger_context_id": trigger_context_id.to_string(),
        "event": event_data,
    });
    let mut initial_results = HashMap::new();
    initial_results.insert(trigger_module_id, seed);

    tracing::info!(
        "🔗 Chaining workflow {} from trigger module {} (context: {})",
        workflow_id,
        trigger_module_id,
        trigger_context_id
    );

    // Create a workflow execution record for this chain run.
    // L-29: spawn the initial INSERT + linkage UPDATE so push-notification
    // handlers (Gmail 10s, GCal 30s) don't stall on slow DB writes
    // before the chain dispatch even starts. The engine doesn't read
    // these rows until much later (status/output writes after run-loop
    // completes), and the trigger handler doesn't depend on their
    // success — best-effort with WARN logging is correct.
    let execution_id = Uuid::new_v4();
    {
        let pool = db_pool.clone();
        let trigger_exec_id = trigger_execution_id;
        tokio::spawn(async move {
            // Phase D2: stamp the gate-resolved actor so row attribution
            // matches the engine binding. Pre-fix the column was omitted and
            // the DB auto-stamp trigger filled the user's DEFAULT actor even
            // when the chain ran as the workflow's own actor — so per-actor
            // budget COUNTs (WHERE actor_id = $1) never saw chain runs and
            // the bound actor's caps were under-enforced on the
            // highest-amplification dispatch path.
            if let Err(db_err) = sqlx::query(
                "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status, started_at) \
                 VALUES ($1, $2, $3, $4, 'running', NOW()) ON CONFLICT DO NOTHING",
            )
            .bind(execution_id)
            .bind(workflow_id)
            .bind(user_id)
            .bind(effective_actor_id)
            .execute(&pool)
            .await
            {
                tracing::warn!(
                    target: "talos_engine",
                    event_kind = "chain_dispatch_db_error",
                    op = "insert_workflow_execution",
                    %execution_id,
                    %workflow_id,
                    error = %db_err,
                    "Failed to insert workflow_executions row for chain dispatch"
                );
            }
            // Link the trigger's module execution to this workflow execution
            if let Err(db_err) =
                sqlx::query("UPDATE module_executions SET workflow_execution_id = $1 WHERE id = $2")
                    .bind(execution_id)
                    .bind(trigger_exec_id)
                    .execute(&pool)
                    .await
            {
                tracing::warn!(
                    target: "talos_engine",
                    event_kind = "chain_dispatch_db_error",
                    op = "link_trigger_execution",
                    %execution_id,
                    %trigger_exec_id,
                    error = %db_err,
                    "Failed to link trigger module_execution to chain workflow_execution"
                );
            }
        });
    }

    if let Some(err_msg) = trigger_error {
        // MCP-451: DLP-redact the trigger error string before
        // persistence. Same secret-leak class as MCP-447/448/449/450
        // — upstream API errors carry tokens that must not land in
        // workflow_executions.error_message. The trigger_error arrives
        // as a pre-formed String from the chain dispatcher; we
        // redact at the sink as defence-in-depth so a future caller
        // that forgets to redact doesn't open a leak.
        let redacted = talos_dlp_provider::redact_str(&err_msg);
        // Race-safe finalize via upsert. The `'running'` INSERT for this
        // execution runs in a fire-and-forget tokio::spawn above (L-29 latency
        // optimization), so on this fast trigger-error path a plain UPDATE could
        // run BEFORE that INSERT commits — matching zero rows and orphaning the
        // execution at `'running'` (force-failed only ~30 min later by the stale
        // sweep). Upserting records `'failed'` regardless of insert/finalize
        // ordering; the spawned INSERT's `ON CONFLICT DO NOTHING` then preserves
        // it. The conflict-update WHERE keeps the existing terminal-state guard.
        if let Err(db_err) = sqlx::query(
            "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status, started_at, completed_at, error_message) \
             VALUES ($2, $3, $4, $5, 'failed', NOW(), NOW(), $1) \
             ON CONFLICT (id) DO UPDATE SET status = 'failed', completed_at = NOW(), error_message = $1 \
             WHERE workflow_executions.status NOT IN ('completed', 'failed', 'cancelled', 'resuming')"
        )
        .bind(&redacted)
        .bind(execution_id)
        .bind(workflow_id)
        .bind(user_id)
        .bind(effective_actor_id)
        .execute(db_pool)
        .await {
            tracing::error!("Database operation failed in engine: {}", db_err);
        }
        return Ok(());
    }

    match crate::nats_run::run_with_seed_via_nats(
        &engine,
        nats_client.clone(),
        worker_shared_key.clone(),
        initial_results,
        execution_id,
    )
    .await
    {
        Ok(ctx) => {
            // Subtract 1 for the pre-seeded trigger node itself.
            let downstream_count = ctx.results.len().saturating_sub(1);
            let output_data = talos_dlp_provider::redact_json(
                &serde_json::to_value(&ctx.results).unwrap_or(serde_json::json!({})),
            );
            // MCP-682: route through the encryption-aware repository so
            // chain-dispatched executions land in `output_data_enc` on
            // Phase A deployments, matching the other writer paths.
            let wf_repo = talos_workflow_repository::WorkflowRepository::new(db_pool.clone())
                .with_encryption(secrets_manager_for_persist);
            // PR #423 sibling: run_with_seed_via_nats shares the engine's
            // run loop, so a wait/confidence-gate pause surfaces here as
            // `ctx.waiting = true` — NOT completed. Persist status='waiting'
            // (row stays resumable) and skip the terminal "chain complete"
            // log on that branch.
            if ctx.waiting {
                tracing::info!(
                    "Workflow {} chain paused (waiting) — {} downstream node(s) ran; \
                     awaiting external resume/approval",
                    workflow_id,
                    downstream_count
                );
                if let Err(db_err) = wf_repo
                    .mark_execution_waiting(execution_id, &output_data)
                    .await
                {
                    tracing::error!("Database operation failed in engine: {}", db_err);
                }
            } else {
                tracing::info!(
                    "✅ Workflow {} chain complete — {} downstream node(s) ran",
                    workflow_id,
                    downstream_count
                );
                if let Err(db_err) = wf_repo
                    .mark_execution_completed(execution_id, &output_data)
                    .await
                {
                    tracing::error!("Database operation failed in engine: {}", db_err);
                }
            }
            Ok(())
        }
        Err(e) => {
            // MCP-451: DLP-redact the engine run error before
            // persistence. Mirrors the success path which already
            // uses redact_json above (line ~475).
            let redacted = talos_dlp_provider::redact_str(&e.to_string());
            // Race-safe finalize via upsert (see the trigger-error path above):
            // run_with_seed_via_nats can fail fast (NATS unavailable, invalid
            // graph) before the spawned `'running'` INSERT commits, so a plain
            // UPDATE could orphan the row at `'running'`. Upsert is correct in
            // either ordering.
            if let Err(db_err) = sqlx::query(
                "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status, started_at, completed_at, error_message) \
                 VALUES ($2, $3, $4, $5, 'failed', NOW(), NOW(), $1) \
                 ON CONFLICT (id) DO UPDATE SET status = 'failed', completed_at = NOW(), error_message = $1 \
                 WHERE workflow_executions.status NOT IN ('completed', 'failed', 'cancelled', 'resuming')"
            )
            .bind(&redacted)
            .bind(execution_id)
            .bind(workflow_id)
            .bind(user_id)
            .bind(effective_actor_id)
            .execute(db_pool)
            .await {
    tracing::error!("Database operation failed in engine: {}", db_err);
}
            // The DB trigger trg_cancel_siblings_on_workflow_fail (migration
            // 20260327000001_cancel_siblings_on_workflow_fail.sql) atomically cancels
            // all still-running module_executions when workflow_executions.status changes
            // to 'failed'.  That trigger fires on the UPDATE above and covers every
            // failure path across the codebase.  The explicit UPDATE below is kept as
            // defense-in-depth for environments where the migration hasn't been applied yet.
            if let Err(db_err) = sqlx::query(
                "UPDATE module_executions \
                 SET status = 'cancelled', \
                     completed_at = NOW(), \
                     error_message = 'Workflow failed — parallel sibling cancelled' \
                 WHERE workflow_execution_id = $1 AND status = 'running'",
            )
            .bind(execution_id)
            .execute(db_pool)
            .await
            {
                tracing::warn!(execution_id = %execution_id, error = %db_err,
                    "Failed to cancel running sibling module_executions after workflow failure");
            }
            Err(e.to_string())
        }
    }
}
