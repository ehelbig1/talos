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

// ─────────────────────────────────────────────────────────────────────────────
// Pure planning: what this walker will and will not chain (2026-09-10).
//
// The chain walker executes the MODULE-ONLY subgraph of a workflow: it adds
// one engine node per distinct module UUID and wires only the edges whose
// BOTH endpoints are module nodes. `system:*` nodes (collect, sub_workflow,
// judge, …) are not chained here — they belong to the full engine load path.
// Before this planner existed the walker resolved the actor, built the
// engine, spawned the `workflow_executions` INSERT and only THEN learned, from
// the engine's own cycle check, that the graph could not run — so every
// module-bound dispatch left a WARN and a `failed` execution row per
// unrunnable workflow. Measured on the dev fleet 2026-09-10: one webhook POST
// bound to the echo module matched five draft stress workflows; 5 of their 6
// edges touch a `system:*` node (each logged as a WARN "edge skipped"), and
// one — `stress-03-conditional`, two nodes running the SAME module with an
// edge between them — collapsed into a self-loop and failed as "workflow
// graph contains a cycle" on every dispatch.
//
// That collapse is a stated LIMIT of this walker, not a graph defect: engine
// nodes are keyed by module id because the seeded trigger result is keyed by
// `trigger_module_id`, so two nodes running one module become one node and an
// edge between them a self-loop. The planner dedupes such nodes (first rf id
// wins) and reports the cyclic case ONCE, before any DB work, as a skip.
// ─────────────────────────────────────────────────────────────────────────────

/// A module-backed node this walker will add to the chain engine.
#[derive(Debug, Clone)]
pub struct ChainModuleNode {
    /// React Flow node id (the graph's string id).
    pub rf_id: String,
    /// The module the node runs — also the engine node id on this path.
    pub module_id: Uuid,
    /// The node's JSON, retained so the retry policy can be read from it.
    pub node: Value,
}

/// How one graph edge relates to the module-only subgraph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainEdgeClass {
    /// Both endpoints are module nodes — wired into the chain engine.
    ModuleToModule { src: Uuid, tgt: Uuid },
    /// At least one endpoint is a node the graph DECLARES but this walker
    /// does not chain (a `system:*` node, or a node with no module id).
    /// EXPECTED on this path — logged at DEBUG, never WARN.
    SystemEndpoint { src_rf: String, tgt_rf: String },
    /// An endpoint names an rf id that appears in no node at all — a
    /// genuinely broken graph, still worth a WARN.
    Dangling {
        src_rf: String,
        tgt_rf: String,
        src_found: bool,
        tgt_found: bool,
    },
}

/// Why a matched workflow is NOT dispatched by the chain walker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainSkip {
    /// The module id matched the graph text but no node runs it (an id
    /// embedded in a description or config, not a module node).
    NoTriggerNode,
    /// The module-only subgraph has a cycle, so the engine would refuse it
    /// at `run_with_seed`. `collapsed_self_loops` counts the edges that
    /// became self-loops because both endpoints run the same module — the
    /// walker's keying limit rather than an authored loop.
    CyclicModuleGraph { collapsed_self_loops: usize },
}

impl ChainSkip {
    /// Stable `event_kind` token for the skip log line.
    pub fn event_kind(&self) -> &'static str {
        match self {
            ChainSkip::NoTriggerNode => "chain_skipped_no_trigger_node",
            ChainSkip::CyclicModuleGraph { .. } => "chain_skipped_cyclic_module_graph",
        }
    }
}

/// The plan for one matched workflow: nodes to add, edges classified, and
/// the verdict on whether to dispatch at all.
#[derive(Debug, Clone)]
pub struct ChainPlan {
    /// Distinct module nodes, deduped by `module_id` (first rf id wins).
    pub module_nodes: Vec<ChainModuleNode>,
    /// `(rf_id, module_id)` of nodes dropped by the dedupe — the trigger
    /// result is keyed by module id, so a second node on the same module
    /// cannot be represented on this path.
    pub collapsed_duplicates: Vec<(String, Uuid)>,
    /// Every edge in the graph, classified.
    pub edges: Vec<ChainEdgeClass>,
    /// The trigger module runs in this graph.
    pub has_trigger: bool,
    /// At least one OTHER module node exists (something to chain into).
    pub has_downstream: bool,
    /// `Some` when the walker must not dispatch this workflow.
    pub skip: Option<ChainSkip>,
}

/// Read the module UUID a graph node runs, if any. May be stored under
/// `type` (save v1) or `data.moduleId` (save v2); a non-UUID `type` such as
/// `talosNode` or `system:collect` is not a module.
fn node_module_id(node: &Value) -> Option<Uuid> {
    node.get("type")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .or_else(|| {
            node.get("data")
                .and_then(|d| d.get("moduleId"))
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok())
        })
}

/// Kahn's algorithm over the deduped module-id graph. Self-loops count as
/// cycles (a node with a self-edge never reaches in-degree zero).
fn module_graph_is_cyclic(nodes: &[Uuid], edges: &[(Uuid, Uuid)]) -> bool {
    let mut indeg: HashMap<Uuid, usize> = nodes.iter().map(|n| (*n, 0)).collect();
    let mut out: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for (s, t) in edges {
        if !indeg.contains_key(s) || !indeg.contains_key(t) {
            continue;
        }
        *indeg.get_mut(t).expect("target present") += 1;
        out.entry(*s).or_default().push(*t);
    }
    let mut ready: Vec<Uuid> = indeg
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(n, _)| *n)
        .collect();
    let mut visited = 0usize;
    while let Some(n) = ready.pop() {
        visited += 1;
        if let Some(ts) = out.get(&n) {
            for t in ts {
                let d = indeg.get_mut(t).expect("target present");
                *d -= 1;
                if *d == 0 {
                    ready.push(*t);
                }
            }
        }
    }
    visited != nodes.len()
}

/// Classify a workflow graph for the chain walker. Pure: no I/O, no logging.
///
/// `graph` is the parsed `workflows.graph_json`. Nodes with a missing `id`
/// are ignored, so an edge naming them reads as dangling.
pub fn plan_workflow_chain(graph: &Value, trigger_module_id: Uuid) -> ChainPlan {
    use std::collections::HashSet;
    let empty = vec![];
    let nodes = graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .unwrap_or(&empty);
    let edges = graph
        .get("edges")
        .and_then(|e| e.as_array())
        .unwrap_or(&empty);

    let mut rf_to_module: HashMap<String, Uuid> = HashMap::new();
    let mut declared: HashSet<String> = HashSet::new();
    let mut module_nodes: Vec<ChainModuleNode> = Vec::new();
    let mut seen_modules: HashSet<Uuid> = HashSet::new();
    let mut collapsed_duplicates: Vec<(String, Uuid)> = Vec::new();

    for node in nodes {
        let rf_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if rf_id.is_empty() {
            continue;
        }
        declared.insert(rf_id.to_string());
        if let Some(module_id) = node_module_id(node) {
            rf_to_module.insert(rf_id.to_string(), module_id);
            if seen_modules.insert(module_id) {
                module_nodes.push(ChainModuleNode {
                    rf_id: rf_id.to_string(),
                    module_id,
                    node: node.clone(),
                });
            } else {
                collapsed_duplicates.push((rf_id.to_string(), module_id));
            }
        }
    }

    let has_trigger = seen_modules.contains(&trigger_module_id);
    let has_downstream = seen_modules.iter().any(|m| *m != trigger_module_id);

    let mut classified = Vec::with_capacity(edges.len());
    let mut module_edges: Vec<(Uuid, Uuid)> = Vec::new();
    let mut collapsed_self_loops = 0usize;
    for edge in edges {
        let src_rf = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let tgt_rf = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
        match (rf_to_module.get(src_rf), rf_to_module.get(tgt_rf)) {
            (Some(&src), Some(&tgt)) => {
                if src == tgt && src_rf != tgt_rf {
                    collapsed_self_loops += 1;
                }
                module_edges.push((src, tgt));
                classified.push(ChainEdgeClass::ModuleToModule { src, tgt });
            }
            _ => {
                let src_found = declared.contains(src_rf);
                let tgt_found = declared.contains(tgt_rf);
                if src_found && tgt_found {
                    classified.push(ChainEdgeClass::SystemEndpoint {
                        src_rf: src_rf.to_string(),
                        tgt_rf: tgt_rf.to_string(),
                    });
                } else {
                    classified.push(ChainEdgeClass::Dangling {
                        src_rf: src_rf.to_string(),
                        tgt_rf: tgt_rf.to_string(),
                        src_found,
                        tgt_found,
                    });
                }
            }
        }
    }

    let skip = if !has_trigger {
        Some(ChainSkip::NoTriggerNode)
    } else {
        let ids: Vec<Uuid> = module_nodes.iter().map(|n| n.module_id).collect();
        if module_graph_is_cyclic(&ids, &module_edges) {
            Some(ChainSkip::CyclicModuleGraph {
                collapsed_self_loops,
            })
        } else {
            None
        }
    };

    ChainPlan {
        module_nodes,
        collapsed_duplicates,
        edges: classified,
        has_trigger,
        has_downstream,
        skip,
    }
}

/// The chain run's `workflow_executions` row, recording WHICH module execution
/// fired it on the run's own row (`triggered_by_module_execution_id`).
///
/// Until 2026-09-11 this link was written the other way round — `UPDATE
/// module_executions SET workflow_execution_id = <chain run> WHERE id =
/// <trigger>` — and that rewrite broke the WORM audit ledger's key space: the
/// worker seals a job's chain under `genesis_hash(workflow_execution_id, job_id)`
/// with the ids ON THE WIRE, and a standalone (module-bound webhook / push)
/// dispatch is signed with `workflow_execution_id = job_id`. Re-parenting the
/// row after the seal made the verifier expect `genesis(chain_run, job)` where
/// the worker had written `genesis(job, job)`, so every module-bound dispatch
/// that fired a chain verified as `genesis_mismatch` — "possible tampering" —
/// on a `critical`-guarded control (3 of 3 such rows in the 30-day window,
/// every one of the fleet's post-partition chain-verification failures).
///
/// `module_executions.workflow_execution_id` is therefore WRITE-ONCE: the
/// value the dispatch carried is the value the ledger was sealed under, and
/// nothing may move it afterwards. `ON CONFLICT DO NOTHING` because the
/// trigger-error and engine-error paths upsert the same id with a terminal
/// status and must win whatever the spawn ordering.
pub async fn insert_chain_execution_row(
    pool: &sqlx::Pool<sqlx::Postgres>,
    execution_id: Uuid,
    workflow_id: Uuid,
    user_id: Uuid,
    effective_actor_id: Option<Uuid>,
    triggered_by_module_execution_id: Uuid,
) -> Result<(), sqlx::Error> {
    // Phase D2: stamp the gate-resolved actor so row attribution matches the
    // engine binding (pre-fix the DB trigger filled the user's DEFAULT actor
    // and per-actor budget COUNTs never saw chain runs).
    sqlx::query(
        "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, actor_id, status, started_at, triggered_by_module_execution_id) \
         VALUES ($1, $2, $3, $4, 'running', NOW(), $5) ON CONFLICT DO NOTHING",
    )
    .bind(execution_id)
    .bind(workflow_id)
    .bind(user_id)
    .bind(effective_actor_id)
    .bind(triggered_by_module_execution_id)
    .execute(pool)
    .await
    .map(|_| ())
}

/// Find all workflows that contain `trigger_module_id` and execute their
/// downstream nodes in-process, with `event_data` pre-seeded as the trigger
/// module's output.
///
/// `trigger_context_id` is an opaque identifier used only for log messages
/// (e.g., a webhook channel UUID or a scheduled job ID).
///
/// This function is best-effort — errors are logged as warnings and do not
/// propagate to the caller.
///
/// # Bounds
///
/// Every caller (`talos-webhooks` router step 12, the three
/// `talos-google-calendar` push handlers) runs this inside `tokio::spawn`, so
/// it is never awaited on an HTTP response path. Within it: at most
/// `TALOS_CHAIN_MAX_WORKFLOWS` (default 50) workflows per dispatch, at most
/// `TALOS_CHAIN_CONCURRENCY` (default 8) chains in flight, and each chain
/// engine carries the engine defaults — `DEFAULT_WORKFLOW_EXECUTION_TIMEOUT_SECS`
/// (300 s) and `DEFAULT_MAX_WORKFLOW_NODES` (500) — because `for_skip_load`
/// uses `TimeoutPolicy::Honor` with no graph-level override on this path.
/// Unrunnable graphs (no trigger node, cyclic module subgraph) are skipped by
/// [`plan_workflow_chain`] BEFORE the auth resolve, the engine build and the
/// execution-row INSERT.
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

    // The liveness predicate has ONE home — `talos_workflow_liveness`
    // (check 87). It is in SQL rather than classified in Rust because of the
    // LIMIT directly below: this is a capped FAN-OUT, not a by-id dispatch, so
    // filtering after the read would let retired or paused workflows consume
    // cap slots and silently displace live ones from the chain set.
    //
    // 2026-09-10: moved from `not_retired_sql` (archived-only) to
    // `dispatchable_sql` (`status <> 'archived' AND is_enabled`), which is the
    // predicate the workflow-bound trigger gate already applies
    // (`OrchestrationError::WorkflowNotLive`). Before this an operator's
    // `disable_workflow` stopped the workflow's own webhook/schedule but NOT a
    // module-bound webhook chaining into it. Latent on the reference fleet
    // (no workflow is disabled) and stated as a behaviour change. As before,
    // an excluded workflow is simply not in the fan-out and NO per-workflow
    // refusal is counted (`talos_dispatch_refused_total` has no `chain`
    // label). This is the path every Google Calendar push notification and
    // every webhook MODULE dispatch fans out through.
    //
    // Why `graph_json LIKE` and not the `workflow_module_refs` junction: the
    // junction is written only by the GraphQL save hook
    // (`sync_workflow_module_refs`) — the MCP graph mutations do not maintain
    // it — so keying the fan-out on it would silently drop chains for every
    // MCP-authored workflow. The LIKE is a text prefilter (a UUID has no
    // false positives worth the name) and `plan_workflow_chain` then requires
    // an actual module NODE running the trigger before anything is dispatched.
    // Measured 2026-09-10: 0.2 ms over 36 workflows — the scan is not the cost
    // on this path; the per-workflow auth resolve and engine build are, which
    // is why the plan runs before both.
    let dispatchable = talos_workflow_liveness::dispatchable_sql(None);
    let workflows = match sqlx::query_as::<_, (Uuid, String, Option<Uuid>)>(&format!(
        "SELECT id, graph_json, actor_id \
         FROM workflows \
         WHERE user_id = $1 AND graph_json LIKE $2 AND {dispatchable} \
         ORDER BY updated_at DESC, id DESC \
         LIMIT $3"
    ))
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

/// Read a chain node's retry policy from its graph JSON, applying the
/// unbudgeted / budgeted caps. Lifted verbatim out of the node loop so the
/// loop can iterate a [`ChainPlan`]; every constant and comment is unchanged.
fn read_chain_retry_policy(node: &Value, workflow_actor_id: Option<Uuid>) -> Option<RetryPolicy> {
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
        // Only `retry_count` answers "how many". The other
        // three keys answer "how far apart" or "when", so
        // a node declaring only those leaves the count
        // UNDECLARED (`None`) and the method-aware
        // classifier answers it at dispatch, exactly as it
        // does for a node with no retry keys at all.
        // Pre-fix this synthesised 2 for ANY capability
        // world — including governance / messaging /
        // database, which fail closed to 0 precisely so a
        // retry cannot double-fire a non-idempotent send.
        // Sibling of the same defect in
        // `talos-workflow-engine::graph_parser`.
        //
        // Both caps below clamp a DECLARED value only:
        // they exist to bound an absurd author-supplied
        // count, and there is nothing to bound when the
        // author supplied nothing. Clamping `None` into a
        // number here would reintroduce the invented
        // count. The classifier's own answers (0 or 2) sit
        // under both caps, so no resolved value moves.
        let max_retries = retry_count.map(|n| {
            if workflow_actor_id.is_none() {
                n.min(MAX_RETRIES_UNBUDGETED)
            } else {
                // MCP-1174: even with an owning actor, cap
                // the absolute count to prevent the
                // 4-billion-retry foot-gun the MCP-962
                // saturation alone left exposed.
                n.min(MAX_RETRIES_BUDGETED)
            }
        });
        Some(RetryPolicy {
            max_retries,
            backoff_ms: retry_backoff.unwrap_or(talos_workflow_engine_core::DEFAULT_BACKOFF_MS),
            retry_condition,
            retry_delay_expression,
        })
    } else {
        None
    }
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
    // Plan FIRST — pure, no I/O. A workflow the walker cannot run (no node
    // runs the trigger module; cyclic module subgraph) is skipped here, before
    // the auth resolve, the engine build and the execution-row INSERT that
    // used to precede the engine's own cycle check.
    let graph: Value =
        serde_json::from_str(graph_json).map_err(|e| format!("Invalid graph_json: {}", e))?;
    let plan = plan_workflow_chain(&graph, trigger_module_id);
    if let Some(skip) = &plan.skip {
        match skip {
            ChainSkip::NoTriggerNode => {
                // The module id matched the graph TEXT but no node runs it.
                tracing::debug!(
                    workflow_id = %workflow_id,
                    trigger_module_id = %trigger_module_id,
                    "workflow_chains: workflow mentions the trigger module but no node runs it — nothing to chain"
                );
            }
            ChainSkip::CyclicModuleGraph {
                collapsed_self_loops,
            } => {
                // ONE line per (workflow, dispatch), with the id, and no
                // `failed` execution row. `collapsed_self_loops > 0` means the
                // cycle is this walker's module-id keying (two nodes on one
                // module with an edge between them), not an authored loop.
                tracing::warn!(
                    target: "talos_engine",
                    event_kind = skip.event_kind(),
                    workflow_id = %workflow_id,
                    trigger_module_id = %trigger_module_id,
                    trigger_context_id = %trigger_context_id,
                    module_nodes = plan.module_nodes.len(),
                    collapsed_self_loops,
                    "workflow_chains: module subgraph is cyclic — workflow skipped for this dispatch \
                     (an edge between two nodes running the SAME module collapses to a self-loop on \
                     the chain path; give each chained step its own module or route the workflow \
                     through its own trigger instead of a module-bound one)"
                );
            }
        }
        return Ok(());
    }
    if !plan.collapsed_duplicates.is_empty() {
        tracing::debug!(
            workflow_id = %workflow_id,
            collapsed = ?plan.collapsed_duplicates,
            "workflow_chains: nodes sharing a module id collapsed into one engine node"
        );
    }

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
        match talos_workflow_authorization::resolve_effective_actor(
            &workflow_repo_for_auth,
            &actor_repo,
            db_pool,
            workflow_actor_id,
            user_id,
            graph_json,
        )
        .await
        {
            Ok(resolved) => resolved,
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
    for n in &plan.module_nodes {
        tracing::debug!(
            rf_id = %n.rf_id,
            module_id = %n.module_id,
            "workflow_chains: mapped node"
        );
        let retry_policy = read_chain_retry_policy(&n.node, workflow_actor_id);
        engine.add_node(n.module_id, None, retry_policy, None);
    }

    tracing::debug!(
        has_trigger = plan.has_trigger,
        has_downstream = plan.has_downstream,
        nodes_mapped = plan.module_nodes.len(),
        "workflow_chains: node mapping complete"
    );

    // Wire only module→module edges. A `system:*` endpoint is EXPECTED here
    // (this walker chains the module subgraph only) and is DEBUG; a dangling
    // endpoint is a broken graph and stays WARN.
    let mut edges_added = 0usize;
    for edge in &plan.edges {
        match edge {
            ChainEdgeClass::ModuleToModule { src, tgt } => {
                tracing::debug!(src = %src, tgt = %tgt, "workflow_chains: edge wired");
                if let Err(e) = engine.add_edge(
                    *src,
                    *tgt,
                    EdgeLogic {
                        source_handle: "output".to_string(),
                        target_handle: "input".to_string(),
                        mapping: None,
                        condition: None,
                        edge_type: Default::default(),
                    },
                ) {
                    // Both endpoints were just added above; unreachable in
                    // practice, but a dropped edge changes the run and must
                    // not be silent.
                    tracing::warn!(src = %src, tgt = %tgt, error = %e, "workflow_chains: add_edge refused");
                } else {
                    edges_added += 1;
                }
            }
            ChainEdgeClass::SystemEndpoint { src_rf, tgt_rf } => {
                tracing::debug!(
                    src_rf,
                    tgt_rf,
                    "workflow_chains: edge touches a non-module node — not chained on this path"
                );
            }
            ChainEdgeClass::Dangling {
                src_rf,
                tgt_rf,
                src_found,
                tgt_found,
            } => {
                tracing::warn!(
                    workflow_id = %workflow_id,
                    src_rf,
                    tgt_rf,
                    src_found,
                    tgt_found,
                    "workflow_chains: edge endpoint names no node in the graph — edge skipped"
                );
            }
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
    // The JoinHandle is KEPT (2026-09-10): the INSERT still overlaps the
    // engine run, but it is awaited before any finalize UPDATE below. Without
    // that ordering a chain with ZERO downstream module nodes — which
    // `run_with_seed_via_nats` completes in microseconds — ran
    // `mark_execution_completed` BEFORE this INSERT committed; the guarded
    // UPDATE matched no row, the INSERT then landed as 'running', and the
    // row sat there until the stale sweep force-failed it an hour later.
    // Observed live on the dev fleet: three stress-* chains stuck 'running'
    // after one module-bound webhook. The trigger-error path below already
    // defends itself with an upsert; the success and engine-error paths did
    // not.
    let row_insert = {
        let pool = db_pool.clone();
        let trigger_exec_id = trigger_execution_id;
        tokio::spawn(async move {
            if let Err(db_err) = insert_chain_execution_row(
                &pool,
                execution_id,
                workflow_id,
                user_id,
                effective_actor_id,
                trigger_exec_id,
            )
            .await
            {
                tracing::warn!(
                    target: "talos_engine",
                    event_kind = "chain_dispatch_db_error",
                    op = "insert_workflow_execution",
                    %execution_id,
                    %workflow_id,
                    %trigger_exec_id,
                    error = %db_err,
                    "Failed to insert workflow_executions row for chain dispatch"
                );
            }
        })
    };

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
            "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status, started_at, completed_at, error_message, triggered_by_module_execution_id) \
             VALUES ($2, $3, $4, $5, 'failed', NOW(), NOW(), $1, $6) \
             ON CONFLICT (id) DO UPDATE SET status = 'failed', completed_at = NOW(), error_message = $1 \
             WHERE workflow_executions.status NOT IN ('completed', 'failed', 'cancelled', 'resuming')"
        )
        .bind(&redacted)
        .bind(execution_id)
        .bind(workflow_id)
        .bind(user_id)
        .bind(effective_actor_id)
        .bind(trigger_execution_id)
        .execute(db_pool)
        .await {
            tracing::error!("Database operation failed in engine: {}", db_err);
        }
        return Ok(());
    }

    let run_result = crate::nats_run::run_with_seed_via_nats(
        &engine,
        nats_client.clone(),
        worker_shared_key.clone(),
        initial_results,
        execution_id,
    )
    .await;

    // Ordering guard (see the JoinHandle comment above): the 'running' row
    // must exist before any of the finalize writes below, or a fast chain
    // finalizes nothing and the row is orphaned at 'running'. A JoinError here
    // means the INSERT task panicked; the finalize is still attempted (the
    // failure branch upserts) and the panic is reported rather than hidden.
    if let Err(join_err) = row_insert.await {
        tracing::warn!(
            target: "talos_engine",
            event_kind = "chain_dispatch_db_error",
            op = "await_insert_workflow_execution",
            %execution_id,
            %workflow_id,
            error = %join_err,
            "chain execution-row INSERT task did not complete; finalize may orphan the row"
        );
    }

    match run_result {
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
                "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status, started_at, completed_at, error_message, triggered_by_module_execution_id) \
                 VALUES ($2, $3, $4, $5, 'failed', NOW(), NOW(), $1, $6) \
                 ON CONFLICT (id) DO UPDATE SET status = 'failed', completed_at = NOW(), error_message = $1 \
                 WHERE workflow_executions.status NOT IN ('completed', 'failed', 'cancelled', 'resuming')"
            )
            .bind(&redacted)
            .bind(execution_id)
            .bind(workflow_id)
            .bind(user_id)
            .bind(effective_actor_id)
            .bind(trigger_execution_id)
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
            if let Err(db_err) = talos_workflow_repository::cancel_running_module_executions(
                db_pool,
                execution_id,
                talos_workflow_repository::SiblingCancelReason::WorkflowFailed,
            )
            .await
            {
                tracing::warn!(execution_id = %execution_id, error = %db_err,
                    "Failed to cancel running sibling module_executions after workflow failure");
            }
            Err(e.to_string())
        }
    }
}

#[cfg(test)]
mod plan_tests {
    //! Pure classification tests for [`plan_workflow_chain`]. The graph shapes
    //! below are the ones measured on the dev fleet 2026-09-10 (five draft
    //! `stress-*` workflows matched by one echo-module webhook), so a
    //! regression here reproduces the WARN storm the planner exists to stop.
    use super::*;
    use serde_json::json;

    const ECHO: &str = "0dc4dd90-4b57-4f25-bfd8-b0faa4e1e683";
    const OTHER: &str = "8aa34ddb-3b15-494f-a6be-3fb9a2980572";

    fn echo() -> Uuid {
        Uuid::parse_str(ECHO).unwrap()
    }

    fn module_node(id: &str, module: &str) -> Value {
        json!({ "id": id, "type": "talosNode", "data": { "moduleId": module } })
    }

    fn system_node(id: &str, kind: &str) -> Value {
        json!({ "id": id, "type": format!("system:{kind}"), "data": {} })
    }

    fn edge(s: &str, t: &str) -> Value {
        json!({ "source": s, "target": t })
    }

    /// `stress-01-echo`: echo → system:collect. The edge is EXPECTED on this
    /// path (the walker chains modules only) — a system endpoint, not a
    /// dangling one, and the workflow still dispatches.
    #[test]
    fn an_edge_into_a_system_node_is_classified_as_system_endpoint_not_dangling() {
        let g = json!({
            "nodes": [module_node("echo", ECHO), system_node("verify_collect", "collect")],
            "edges": [edge("echo", "verify_collect")],
        });
        let plan = plan_workflow_chain(&g, echo());
        assert_eq!(plan.skip, None);
        assert!(plan.has_trigger);
        assert!(!plan.has_downstream);
        assert_eq!(
            plan.edges,
            vec![ChainEdgeClass::SystemEndpoint {
                src_rf: "echo".into(),
                tgt_rf: "verify_collect".into(),
            }]
        );
    }

    /// An endpoint that names NO node at all is a broken graph and keeps WARN.
    #[test]
    fn an_edge_naming_an_undeclared_node_is_dangling_with_per_side_flags() {
        let g = json!({
            "nodes": [module_node("echo", ECHO)],
            "edges": [edge("echo", "ghost")],
        });
        let plan = plan_workflow_chain(&g, echo());
        assert_eq!(
            plan.edges,
            vec![ChainEdgeClass::Dangling {
                src_rf: "echo".into(),
                tgt_rf: "ghost".into(),
                src_found: true,
                tgt_found: false,
            }]
        );
        assert_eq!(plan.skip, None);
    }

    /// A module → module DAG wires and has something downstream.
    #[test]
    fn a_module_to_module_dag_is_wired_and_not_skipped() {
        let g = json!({
            "nodes": [module_node("a", ECHO), module_node("b", OTHER)],
            "edges": [edge("a", "b")],
        });
        let plan = plan_workflow_chain(&g, echo());
        assert_eq!(plan.skip, None);
        assert!(plan.has_downstream);
        assert_eq!(
            plan.edges,
            vec![ChainEdgeClass::ModuleToModule {
                src: echo(),
                tgt: Uuid::parse_str(OTHER).unwrap(),
            }]
        );
        assert_eq!(plan.module_nodes.len(), 2);
    }

    /// `stress-03-conditional`: two nodes running the SAME module with an edge
    /// between them. On this path both collapse into one engine node and the
    /// edge becomes a self-loop — the real cause of the live "workflow graph
    /// contains a cycle" WARN. The planner must say so ONCE and dispatch
    /// nothing, and must attribute the cycle to the collapse.
    #[test]
    fn two_nodes_on_one_module_with_an_edge_collapse_into_a_cyclic_skip() {
        let g = json!({
            "nodes": [module_node("gate", ECHO), module_node("maybe_skipped", ECHO)],
            "edges": [edge("gate", "maybe_skipped")],
        });
        let plan = plan_workflow_chain(&g, echo());
        assert_eq!(
            plan.skip,
            Some(ChainSkip::CyclicModuleGraph {
                collapsed_self_loops: 1
            })
        );
        assert_eq!(plan.module_nodes.len(), 1, "deduped to one engine node");
        assert_eq!(
            plan.collapsed_duplicates,
            vec![("maybe_skipped".to_string(), echo())]
        );
        assert_eq!(
            plan.skip.as_ref().unwrap().event_kind(),
            "chain_skipped_cyclic_module_graph"
        );
    }

    /// An authored cycle between two DIFFERENT modules is also a skip, with
    /// zero collapsed self-loops so the log line does not blame the keying.
    #[test]
    fn an_authored_two_cycle_between_distinct_modules_is_a_cyclic_skip() {
        let g = json!({
            "nodes": [module_node("a", ECHO), module_node("b", OTHER)],
            "edges": [edge("a", "b"), edge("b", "a")],
        });
        let plan = plan_workflow_chain(&g, echo());
        assert_eq!(
            plan.skip,
            Some(ChainSkip::CyclicModuleGraph {
                collapsed_self_loops: 0
            })
        );
    }

    /// `stress-05-parent`: echo ⇄ system:sub_workflow. The cycle runs THROUGH
    /// a system node, which this walker does not chain, so the module
    /// subgraph is a single node and NOT cyclic — both edges are system
    /// endpoints and the workflow dispatches as a single-node chain.
    #[test]
    fn a_cycle_through_a_system_node_is_not_a_module_cycle() {
        let g = json!({
            "nodes": [module_node("loop_back", ECHO), system_node("call_child", "sub_workflow")],
            "edges": [edge("loop_back", "call_child"), edge("call_child", "loop_back")],
        });
        let plan = plan_workflow_chain(&g, echo());
        assert_eq!(plan.skip, None);
        assert!(plan
            .edges
            .iter()
            .all(|e| matches!(e, ChainEdgeClass::SystemEndpoint { .. })));
    }

    /// The LIKE prefilter matches graph TEXT; a uuid embedded in a description
    /// is not a node running the module and must skip quietly.
    #[test]
    fn a_module_id_mentioned_but_not_run_is_a_no_trigger_skip() {
        let g = json!({
            "nodes": [json!({ "id": "n", "type": "talosNode", "data": {
                "moduleId": OTHER, "description": format!("was {ECHO}") } })],
            "edges": [],
        });
        let plan = plan_workflow_chain(&g, echo());
        assert_eq!(plan.skip, Some(ChainSkip::NoTriggerNode));
        assert!(!plan.has_trigger);
        assert_eq!(
            plan.skip.as_ref().unwrap().event_kind(),
            "chain_skipped_no_trigger_node"
        );
    }

    /// Save-v1 graphs carry the module uuid under `type`; save-v2 under
    /// `data.moduleId`. Both are module nodes; `talosNode`/`system:*` are not.
    #[test]
    fn module_id_is_read_from_type_or_data_module_id() {
        let g = json!({
            "nodes": [
                json!({ "id": "v1", "type": ECHO }),
                module_node("v2", OTHER),
                system_node("sys", "collect"),
                json!({ "id": "plain", "type": "talosNode", "data": {} }),
            ],
            "edges": [edge("v1", "v2"), edge("v2", "plain")],
        });
        let plan = plan_workflow_chain(&g, echo());
        assert_eq!(plan.module_nodes.len(), 2);
        assert_eq!(plan.skip, None);
        assert!(matches!(
            plan.edges[0],
            ChainEdgeClass::ModuleToModule { .. }
        ));
        assert!(matches!(
            plan.edges[1],
            ChainEdgeClass::SystemEndpoint { .. }
        ));
    }

    /// A graph with no `edges` key and no `nodes` key is empty, not an error.
    #[test]
    fn a_graph_without_nodes_or_edges_is_a_quiet_no_trigger_skip() {
        let plan = plan_workflow_chain(&json!({}), echo());
        assert_eq!(plan.skip, Some(ChainSkip::NoTriggerNode));
        assert!(plan.edges.is_empty());
    }
}
