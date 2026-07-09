//! Replay service: runs the last N completed executions of a module
//! (or of a node within a workflow) against the *current* WASM bytes
//! and diffs each replayed output against the stored one.
//!
//! Owns the orchestration that previously lived inline in
//! `talos-mcp-handlers/src/sandbox.rs::handle_replay_module_regression`
//! and `handle_replay_workflow_mode` (~640 LoC of copy-pasted
//! module loading + secret prefetch + execute-and-diff loop). The
//! per-row replay kernel runs once here, callable from MCP handlers
//! today and from a future GraphQL mutation without protocol
//! branching.
//!
//! Architectural pattern: matches `talos-execution-orchestration`
//! (r295) and `talos-workflow-manifest` (r302) — Arc-injected
//! dependencies, `thiserror` enum mapped to JSON-RPC codes via
//! `jsonrpc_code()`, typed input + outcome structs, and a
//! `user_facing_message()` accessor that collapses internal errors
//! to a generic message so the protocol response cannot leak schema
//! or query detail.
//!
//! Security posture (preserved from the inline handlers verbatim):
//! - `user_id` scoped at SQL layer — caller cannot replay a module or
//!   workflow they do not own, even if they guess its UUID. Catalog
//!   modules (`user_id = NULL`) have no owned execution history and
//!   therefore no rows match the replay query.
//! - `limit` is the caller's responsibility to clamp into a sane
//!   range; the service does not run more replays than asked. The
//!   reference handlers clamp to `[1, 20]`.
//! - Each replay is wrapped in a per-call timeout (caller-supplied,
//!   typically 30 s default, 120 s ceiling) so a stuck replay cannot
//!   monopolise the dispatcher.
//! - Governance / Unknown capability worlds are rejected — they
//!   require the full workflow engine and cannot execute via the
//!   standalone runtime.
//! - Secrets are resolved via [`SecretsManager`] using the caller's
//!   `user_id`, so cross-tenant secret leakage is impossible even via
//!   replay. Pre-fetch happens once per call, not per row.
//!
//! V1 scope for workflow-node replay: linear pipelines only. A target
//! node with more than one predecessor (fan-in) returns
//! [`ReplayError::InvalidArg`] with a clear suggestion to replay each
//! predecessor individually.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value as JsonValue;
use thiserror::Error;
use uuid::Uuid;

use talos_capability_world::CapabilityWorld;
use talos_module_repository::ModuleRepository;
use talos_registry::{ModuleRegistry, WasmModule};
use talos_replay_diff::{diff_values, report_to_json, DiffConfig, DEFAULT_IGNORED_FIELDS};
use talos_secrets_manager::SecretsManager;
use talos_workflow_engine::ParallelWorkflowEngine;
use talos_workflow_job_protocol::LlmTier;
use talos_workflow_repository::{find_node_in_array, WorkflowRepository};

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Service-level errors. The `jsonrpc_code()` helper maps each variant
/// to a stable JSON-RPC error code so the MCP handler wrapper stays
/// trivial.
#[derive(Debug, Error)]
pub enum ReplayError {
    /// Caller-supplied argument failed structural validation
    /// (missing field, fan-in node, governance/unknown world, etc.).
    /// Maps to `-32602` (Invalid params).
    #[error("{0}")]
    InvalidArg(String),

    /// Workflow / node / module / template lookup returned no row, or
    /// the row is owned by a different user. Maps to `-32000`. The
    /// distinction between "missing" and "access denied" is
    /// deliberately collapsed in the user-facing message (security:
    /// don't leak existence to non-owners).
    #[error("{0}")]
    NotFound(String),

    /// Required-path repository or runtime call returned an error.
    /// The detail is logged at `error!` level by the service; callers
    /// receive the generic mapped message. Maps to `-32000`.
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl ReplayError {
    /// Stable JSON-RPC error code for protocol wrappers.
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::InvalidArg(_) => -32602,
            Self::NotFound(_) | Self::Internal(_) => -32000,
        }
    }

    /// Generic, callable-safe message for the protocol response.
    /// `Internal` collapses to `"Internal error"` so the response does
    /// not leak schema, query, or runtime-trap detail.
    pub fn user_facing_message(&self) -> String {
        match self {
            Self::InvalidArg(msg) | Self::NotFound(msg) => msg.clone(),
            Self::Internal(_) => "Internal error".to_string(),
        }
    }
}

// -----------------------------------------------------------------------------
// Inputs
// -----------------------------------------------------------------------------

/// Input for [`ReplayService::replay_module`]. The handler is responsible
/// for clamping `limit` and `timeout_secs` to its preferred ranges before
/// constructing this — the service does not second-guess.
pub struct ModuleReplayInput {
    pub module_id: Uuid,
    pub user_id: Uuid,
    pub limit: i64,
    pub timeout_secs: u64,
    pub ignore_fields: Vec<String>,
}

/// Input for [`ReplayService::replay_workflow_node`].
pub struct WorkflowReplayInput {
    pub workflow_id: Uuid,
    pub node_label: String,
    pub user_id: Uuid,
    pub limit: i64,
    pub timeout_secs: u64,
    pub ignore_fields: Vec<String>,
}

// -----------------------------------------------------------------------------
// Outcomes
// -----------------------------------------------------------------------------

/// Per-row replay outcome. `diff` is `Some` for matched/drifted, `None`
/// for errored; `error` is `Some` only for errored.
#[derive(Debug, Serialize)]
pub struct ReplayResultRow {
    pub execution_id: Uuid,
    pub duration_ms: i64,
    pub status: ReplayStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReplayStatus {
    Matched,
    Drifted,
    Errored,
}

/// Summary counters shared by both replay modes.
#[derive(Debug, Default)]
pub struct ReplayCounters {
    pub matched: usize,
    pub drifted: usize,
    pub errored: usize,
}

/// Outcome of [`ReplayService::replay_module`].
pub struct ModuleReplayOutcome {
    pub module_id: Uuid,
    pub module_name: String,
    pub counters: ReplayCounters,
    pub results: Vec<ReplayResultRow>,
}

impl ModuleReplayOutcome {
    pub fn replayed(&self) -> usize {
        self.results.len()
    }
}

/// Outcome of [`ReplayService::replay_workflow_node`].
pub struct WorkflowReplayOutcome {
    pub workflow_name: String,
    pub node_label: String,
    pub module_name: String,
    /// Source node label that fed the target. `None` for root nodes
    /// (replay input came from `__trigger_input__`).
    pub predecessor: Option<String>,
    pub counters: ReplayCounters,
    pub results: Vec<ReplayResultRow>,
}

impl WorkflowReplayOutcome {
    pub fn replayed(&self) -> usize {
        self.results.len()
    }
}

// -----------------------------------------------------------------------------
// Internal types
// -----------------------------------------------------------------------------

/// One row to replay. Held in memory between the SQL fetch and the
/// runtime invocation; no PII beyond what's already on disk.
struct ReplaySample {
    execution_id: Uuid,
    /// What previous nodes produced (or trigger input for root nodes).
    upstream_payload: JsonValue,
    /// Node-level static config (`data` block from the graph).
    node_config: JsonValue,
    /// Output the engine recorded last time.
    stored_output: JsonValue,
}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/// Replay service. Holds Arc-wrapped dependencies; safe to clone (cheap
/// reference-count bumps). Constructed once at controller boot and shared
/// across the MCP handler tree (and any future GraphQL surface).
pub struct ReplayService {
    registry: Arc<ModuleRegistry>,
    workflow_repo: Arc<WorkflowRepository>,
    module_repo: Arc<ModuleRepository>,
    /// MCP-691 (2026-05-13): added to look up the workflow's actor and
    /// its `max_llm_tier` so replay inherits the original ceiling.
    actor_repo: Arc<talos_actor_repository::ActorRepository>,
    secrets_manager: Arc<SecretsManager>,
    runtime: Arc<worker::runtime::TalosRuntime>,
}

impl ReplayService {
    pub fn new(
        registry: Arc<ModuleRegistry>,
        workflow_repo: Arc<WorkflowRepository>,
        module_repo: Arc<ModuleRepository>,
        actor_repo: Arc<talos_actor_repository::ActorRepository>,
        secrets_manager: Arc<SecretsManager>,
        runtime: Arc<worker::runtime::TalosRuntime>,
    ) -> Self {
        Self {
            registry,
            workflow_repo,
            module_repo,
            actor_repo,
            secrets_manager,
            runtime,
        }
    }

    /// MCP-691 (2026-05-13): resolve the LLM tier ceiling to apply to a
    /// replay. Workflows with a bound actor inherit that actor's
    /// `max_llm_tier`; workflows without a bound actor — and module
    /// replay paths — fail-CLOSED to Tier-1 (no external LLM egress).
    /// Pre-fix `LlmTier::default() == Tier2` ran every replay with
    /// external-LLM access enabled, which would silently exfiltrate
    /// stored Tier-1 actor data to api.openai.com if the module's
    /// flow tried an external provider during replay. Operators
    /// running `replay_workflow_node` against a Tier-1 actor's
    /// workflow saw the worker happily POST to OpenAI because the
    /// original tier wasn't threaded into the replay path.
    ///
    /// Fail-CLOSED default for unknown-actor cases mirrors the policy
    /// from `ActorRepository::apply_actor_to_engine`'s contract.
    /// Operators can extend the input shape with an explicit
    /// `force_tier2` flag if a no-actor workflow genuinely needs
    /// external LLM access during replay (no such caller exists today).
    async fn resolve_replay_tier(
        &self,
        workflow_id: Option<Uuid>,
        user_id: Uuid,
    ) -> talos_workflow_job_protocol::LlmTier {
        let Some(wf_id) = workflow_id else {
            return talos_workflow_job_protocol::LlmTier::Tier1;
        };
        let actor_id = match self
            .workflow_repo
            .get_workflow_actor_id(wf_id, user_id)
            .await
        {
            Ok(Some(aid)) => aid,
            Ok(None) => return talos_workflow_job_protocol::LlmTier::Tier1,
            Err(e) => {
                tracing::warn!(
                    workflow_id = %wf_id,
                    error = %e,
                    "MCP-691: workflow actor lookup failed during replay — defaulting to Tier-1"
                );
                return talos_workflow_job_protocol::LlmTier::Tier1;
            }
        };
        match self.actor_repo.get_actor_max_llm_tier(actor_id).await {
            Ok(Some(tier)) => tier,
            Ok(None) => {
                tracing::warn!(
                    %actor_id,
                    "MCP-691: actor row missing during replay — defaulting to Tier-1"
                );
                talos_workflow_job_protocol::LlmTier::Tier1
            }
            Err(e) => {
                tracing::warn!(
                    %actor_id,
                    error = %e,
                    "MCP-691: actor tier lookup failed during replay — defaulting to Tier-1"
                );
                talos_workflow_job_protocol::LlmTier::Tier1
            }
        }
    }

    // ---------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------

    /// Replay the last `limit` completed executions of `module_id`
    /// against the current WASM bytes. Each row's stored input/output
    /// is used to drive the replay and compute a structural diff.
    pub async fn replay_module(
        &self,
        input: ModuleReplayInput,
    ) -> Result<ModuleReplayOutcome, ReplayError> {
        let module = self
            .load_module_with_template_fallback(input.module_id, input.user_id)
            .await?;
        reject_unreplayable_world(&module.capability_world, /* workflow_mode */ false)?;

        let rows = self
            .module_repo
            .list_completed_module_executions(input.module_id, input.user_id, input.limit)
            .await
            .map_err(|e| {
                tracing::error!(
                    "replay_module: list_completed_module_executions failed: {:#}",
                    e
                );
                ReplayError::Internal(e)
            })?;

        if rows.is_empty() {
            return Ok(ModuleReplayOutcome {
                module_id: input.module_id,
                module_name: module.name,
                counters: ReplayCounters::default(),
                results: Vec::new(),
            });
        }

        // Resolve per-row node_config from the workflow graph the row
        // was originally dispatched under. Test-module / ad-hoc rows
        // have NULL workflow_execution_id and fall back to `{}` —
        // the replay will surface a clean error if the module needs
        // config, and the error is captured per-row in the result.
        let mut samples = Vec::with_capacity(rows.len());
        for (exec_id, input_data, output_data, wf_exec_id) in rows {
            let node_config = self
                .lookup_node_config_for_module(wf_exec_id, input.module_id)
                .await
                .unwrap_or_else(|| serde_json::json!({}));

            samples.push(ReplaySample {
                execution_id: exec_id,
                upstream_payload: input_data.unwrap_or(JsonValue::Null),
                node_config,
                stored_output: output_data.unwrap_or(JsonValue::Null),
            });
        }

        let secrets = self.prefetch_secrets(&module, input.user_id).await;
        // MCP-691: module-replay path has no workflow context — pass
        // None so resolve_replay_tier defaults to Tier-1.
        let llm_tier = self.resolve_replay_tier(None, input.user_id).await;
        let results = run_replays(
            &self.runtime,
            &module,
            samples,
            secrets,
            input.timeout_secs,
            &input.ignore_fields,
            llm_tier,
        )
        .await;

        Ok(ModuleReplayOutcome {
            module_id: input.module_id,
            module_name: module.name,
            counters: count(&results),
            results,
        })
    }

    /// Replay the target node of a workflow against the last `limit`
    /// completed workflow executions. The replay input is the
    /// predecessor node's recorded output (or `__trigger_input__` for
    /// root nodes). Linear pipelines only — fan-in fails closed.
    pub async fn replay_workflow_node(
        &self,
        input: WorkflowReplayInput,
    ) -> Result<WorkflowReplayOutcome, ReplayError> {
        if input.node_label.is_empty() {
            return Err(ReplayError::InvalidArg(
                "node_label is required when using workflow_id mode".to_string(),
            ));
        }

        // 1. Load the workflow (ownership check via user_id).
        let wf_row = self
            .workflow_repo
            .get_workflow_name_and_graph(input.workflow_id, input.user_id)
            .await
            .map_err(|e| {
                tracing::error!(
                    "replay_workflow_node: get_workflow_name_and_graph failed: {:#}",
                    e
                );
                ReplayError::Internal(e)
            })?;

        let (wf_name, graph_json_str) = wf_row.ok_or_else(|| {
            ReplayError::NotFound("Workflow not found or access denied".to_string())
        })?;
        let graph: JsonValue = serde_json::from_str(&graph_json_str)
            .map_err(|_| ReplayError::NotFound("Workflow graph_json is invalid".to_string()))?;

        // 2. Locate target node + walk edges.
        let plan = plan_workflow_replay(&graph, &input.node_label)?;

        // 3. Load module via the graph's `type` UUID.
        let module = self
            .load_module_with_template_fallback(plan.module_type_id, input.user_id)
            .await?;
        reject_unreplayable_world(&module.capability_world, /* workflow_mode */ true)?;

        let secrets = self.prefetch_secrets(&module, input.user_id).await;

        // 4. Pull recent completed workflow_executions with output_data.
        let wf_exec_rows = self
            .module_repo
            .list_completed_workflow_executions_with_output(
                input.workflow_id,
                input.user_id,
                input.limit,
            )
            .await
            .map_err(|e| {
                tracing::error!(
                    "replay_workflow_node: list_completed_workflow_executions_with_output failed: {:#}",
                    e
                );
                ReplayError::Internal(e)
            })?;

        if wf_exec_rows.is_empty() {
            return Ok(WorkflowReplayOutcome {
                workflow_name: wf_name,
                node_label: input.node_label,
                module_name: module.name,
                predecessor: plan.predecessor_label,
                counters: ReplayCounters::default(),
                results: Vec::new(),
            });
        }

        // 5. Build samples by reading the predecessor's output (or
        //    trigger input for root nodes) out of `output_data`.
        let mut samples = Vec::with_capacity(wf_exec_rows.len());
        for (wf_exec_id, output_data) in wf_exec_rows {
            let all_outputs = output_data.unwrap_or(serde_json::json!({}));

            let upstream_payload = match plan.predecessor_label.as_deref() {
                Some(pred) => all_outputs.get(pred).cloned().unwrap_or(JsonValue::Null),
                None => all_outputs
                    .get("__trigger_input__")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({})),
            };
            let stored_output = all_outputs
                .get(&input.node_label)
                .cloned()
                .unwrap_or(JsonValue::Null);

            samples.push(ReplaySample {
                execution_id: wf_exec_id,
                upstream_payload,
                node_config: plan.node_config.clone(),
                stored_output,
            });
        }

        // MCP-691: inherit the workflow actor's tier ceiling so a
        // Tier-1 actor's replay can't egress data to external LLM hosts.
        let llm_tier = self
            .resolve_replay_tier(Some(input.workflow_id), input.user_id)
            .await;
        let results = run_replays(
            &self.runtime,
            &module,
            samples,
            secrets,
            input.timeout_secs,
            &input.ignore_fields,
            llm_tier,
        )
        .await;

        Ok(WorkflowReplayOutcome {
            workflow_name: wf_name,
            node_label: input.node_label,
            module_name: module.name,
            predecessor: plan.predecessor_label,
            counters: count(&results),
            results,
        })
    }

    // ---------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------

    /// Load a module via the standard "user-installed first, template
    /// fallback" cascade. Mirrors the `test_module` path. Templates
    /// without a precompiled WASM blob are surfaced as `NotFound` —
    /// callers should `compile_template` first.
    async fn load_module_with_template_fallback(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<WasmModule, ReplayError> {
        if let Ok(m) = self.registry.get_module(module_id, user_id).await {
            return Ok(m);
        }
        let template = self
            .registry
            .get_template_for_user(module_id, user_id)
            .await
            .map_err(|_| ReplayError::NotFound("Module not found or access denied".to_string()))?;
        let wasm_bytes = template.precompiled_wasm.ok_or_else(|| {
            ReplayError::NotFound(
                "Template has no compiled WASM. Use compile_template first.".to_string(),
            )
        })?;
        let inspection = worker::inspect_component(&wasm_bytes);
        Ok(WasmModule {
            name: template.name,
            content_hash: format!("template:{}", module_id),
            wasm_bytes,
            source_code: None,
            template_id: Some(module_id),
            config: None,
            size_bytes: 0,
            max_fuel: 10_000_000,
            max_memory_mb: 128,
            allowed_hosts: template.allowed_hosts,
            allowed_methods: vec![],
            allowed_secrets: template.allowed_secrets,
            requires_approval_for: template.requires_approval_for,
            user_id: None,
            capability_world: inspection.capability_world,
            imported_interfaces: inspection.imported_interfaces,
            dependencies: None,
            oci_url: template.oci_url,
            language: "rust".to_string(),
            integration_name: None,
        })
    }

    /// Best-effort secret prefetch. Empty allowlist → empty map (no DB
    /// hit). DB error → empty map (matches the reference handler) so
    /// a transient secrets outage does not abort replay; modules that
    /// genuinely require a secret will surface a clean per-row error.
    async fn prefetch_secrets(
        &self,
        module: &WasmModule,
        user_id: Uuid,
    ) -> HashMap<String, String> {
        if module.allowed_secrets.is_empty() {
            return HashMap::new();
        }
        match self
            .secrets_manager
            .get_secrets_by_paths(&module.allowed_secrets, Some(user_id))
            .await
        {
            Ok(map) => map,
            Err(e) => {
                tracing::warn!(
                    "replay: secret prefetch failed (continuing with empty map): {:#}",
                    e
                );
                HashMap::new()
            }
        }
    }

    /// For module-mode rows whose original workflow context is known,
    /// rebuild the static `config` block by walking that workflow's
    /// graph for the node whose `type` UUID matches the module. Returns
    /// `None` for ad-hoc rows (no workflow), unparseable graphs, or no
    /// matching node — caller falls back to `{}`.
    async fn lookup_node_config_for_module(
        &self,
        workflow_execution_id: Option<Uuid>,
        module_id: Uuid,
    ) -> Option<JsonValue> {
        let wf_exec_id = workflow_execution_id?;
        let graph_text = self
            .module_repo
            .get_workflow_graph_via_execution_id(wf_exec_id)
            .await
            .ok()
            .flatten()?;
        let graph: JsonValue = serde_json::from_str(&graph_text).ok()?;
        let nodes = graph.get("nodes")?.as_array()?;
        let target = module_id.to_string();
        for node in nodes {
            let node_type = node.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if node_type == target {
                return node.get("data").cloned();
            }
        }
        None
    }
}

// -----------------------------------------------------------------------------
// Pure helpers (testable without DB / runtime)
// -----------------------------------------------------------------------------

/// Pre-computed plan for a workflow-mode replay. Built from the graph
/// JSON before any module/runtime work; lets us fail closed on
/// fan-in or missing nodes without touching the runtime.
#[derive(Debug)]
struct WorkflowReplayPlan {
    /// `type` UUID of the target node — points at the module to replay.
    module_type_id: Uuid,
    /// Static `data` block from the target node — the engine's
    /// `config` wrapper at dispatch time.
    node_config: JsonValue,
    /// Source-side node id whose recorded output feeds the target, or
    /// `None` for root nodes (replay input comes from
    /// `__trigger_input__`).
    predecessor_label: Option<String>,
}

/// Walk the graph, locate the target node, validate fan-in, and
/// extract the predecessor label. Pure — no I/O.
fn plan_workflow_replay(
    graph: &JsonValue,
    node_label: &str,
) -> Result<WorkflowReplayPlan, ReplayError> {
    let nodes = graph
        .get("nodes")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ReplayError::InvalidArg("Workflow has no nodes".to_string()))?;

    let target_node = find_node_in_array(nodes, node_label).ok_or_else(|| {
        let available: Vec<&str> = nodes
            .iter()
            .filter_map(|n| n.get("id").and_then(|v| v.as_str()))
            .collect();
        ReplayError::InvalidArg(format!(
            "Node '{}' not found in workflow. Available: {}",
            node_label,
            available.join(", ")
        ))
    })?;

    let module_type_id: Uuid = target_node
        .get("type")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ReplayError::InvalidArg("Node has no valid type UUID".to_string()))?;

    let node_config = target_node
        .get("data")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let edges = graph.get("edges").and_then(|v| v.as_array());
    let predecessors: Vec<String> = edges
        .map(|es| {
            es.iter()
                .filter_map(|e| {
                    let target = e.get("target").and_then(|v| v.as_str())?;
                    let source = e.get("source").and_then(|v| v.as_str())?;
                    if target == node_label {
                        Some(source.to_string())
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    if predecessors.len() > 1 {
        return Err(ReplayError::InvalidArg(format!(
            "Node '{}' has {} predecessors (fan-in). V1 replay supports linear \
             chains only. Replay each predecessor individually instead.",
            node_label,
            predecessors.len()
        )));
    }
    let predecessor_label = predecessors.into_iter().next();

    Ok(WorkflowReplayPlan {
        module_type_id,
        node_config,
        predecessor_label,
    })
}

/// Reject capability worlds that the standalone runtime cannot
/// execute. Governance / Unknown require the full workflow engine.
/// Workflow-mode and module-mode use slightly different copy because
/// each has a distinct existing surface message — preserve both.
fn reject_unreplayable_world(
    world: &CapabilityWorld,
    workflow_mode: bool,
) -> Result<(), ReplayError> {
    if matches!(
        world,
        CapabilityWorld::Governance | CapabilityWorld::Unknown
    ) {
        let msg = if workflow_mode {
            "governance-node / unknown worlds cannot be replayed"
        } else {
            "governance-node / unknown capability worlds cannot be replayed outside the workflow engine"
        };
        return Err(ReplayError::InvalidArg(msg.to_string()));
    }
    Ok(())
}

/// Compose the per-call ignore set: engine-metadata defaults +
/// caller additions. Owned `Vec<String>` so the closure borrowing
/// the args `Value` can drop early.
fn build_ignore_field_set(caller_ignores: &[String]) -> Vec<String> {
    DEFAULT_IGNORED_FIELDS
        .iter()
        .map(|s: &&str| (*s).to_string())
        .chain(caller_ignores.iter().cloned())
        .collect()
}

/// Sum match/drift/error counters from a result vec.
fn count(results: &[ReplayResultRow]) -> ReplayCounters {
    let mut c = ReplayCounters::default();
    for r in results {
        match r.status {
            ReplayStatus::Matched => c.matched += 1,
            ReplayStatus::Drifted => c.drifted += 1,
            ReplayStatus::Errored => c.errored += 1,
        }
    }
    c
}

// -----------------------------------------------------------------------------
// Replay kernel
// -----------------------------------------------------------------------------

/// Execute one replay per sample, diff against stored output, return
/// per-row results. One `secrets` clone per row (the runtime takes
/// ownership). One DiffConfig built per row (cheap; bounded
/// `max_changed_paths`). Each replay is wrapped in the supplied
/// timeout so a stuck replay cannot stall the loop.
async fn run_replays(
    runtime: &worker::runtime::TalosRuntime,
    module: &WasmModule,
    samples: Vec<ReplaySample>,
    secrets: HashMap<String, String>,
    timeout_secs: u64,
    caller_ignores: &[String],
    llm_tier: LlmTier,
) -> Vec<ReplayResultRow> {
    let all_ignores = build_ignore_field_set(caller_ignores);
    let mut results: Vec<ReplayResultRow> = Vec::with_capacity(samples.len());

    for sample in samples {
        let replay_input = serde_json::json!({
            "input": sample.upstream_payload,
            "config": sample.node_config,
        });

        let start = Instant::now();
        let exec_result = runtime
            .execute_job_with_full_features(
                &module.wasm_bytes,
                module.allowed_hosts.clone(),
                module.allowed_methods.clone(),
                module.max_memory_mb as usize,
                replay_input,
                None,
                None,
                secrets.clone(),
                None,
                Duration::from_secs(timeout_secs),
                worker::runtime::RetryPolicy::default(),
                None,
                worker::runtime::SecurityPolicy::default(),
                None,
                None,
                false,
                None,        // actor_id
                Uuid::nil(), // user_id (controller-internal replay path)
                // MCP-691: inherit the original actor's tier ceiling
                // (caller-resolved). Default Tier-1 for replays without
                // a bound actor; do NOT use LlmTier::default() (Tier-2)
                // which would let stored Tier-1 data egress to external
                // LLM hosts during replay.
                llm_tier,
                // Write ceiling: replay is an operator-invoked regression
                // diagnostic against stored samples, not live actor
                // execution. Run permissively (`Write`) so a workflow that
                // legitimately mutates doesn't surface a spurious
                // write-ceiling refusal in the replay diff; the ceiling
                // gate governs live execution, which the actor binding
                // stamps there.
                talos_workflow_job_protocol::WriteCeiling::Write,
            )
            .await;
        let duration_ms = start.elapsed().as_millis() as i64;

        match exec_result {
            Ok(replayed_output) => {
                let unwrapped = ParallelWorkflowEngine::unwrap_output(&replayed_output);
                let ignore_set: HashSet<&str> = all_ignores.iter().map(String::as_str).collect();
                let cfg = DiffConfig {
                    ignore_fields: ignore_set,
                    max_changed_paths: 64,
                };
                let report = diff_values(&sample.stored_output, unwrapped, &cfg);
                let status = if report.matched {
                    ReplayStatus::Matched
                } else {
                    ReplayStatus::Drifted
                };
                results.push(ReplayResultRow {
                    execution_id: sample.execution_id,
                    duration_ms,
                    status,
                    diff: Some(report_to_json(&report)),
                    error: None,
                });
            }
            Err(e) => results.push(ReplayResultRow {
                execution_id: sample.execution_id,
                duration_ms,
                status: ReplayStatus::Errored,
                diff: None,
                // MCP-577: DLP-scrub the worker error before surfacing
                // through the MCP response. This path bypasses the
                // engine's `DlpExecutionSanitizer::redact_error` (which
                // is wired into the normal trigger / replay / retry
                // flow via `talos-workflow-engine`) because the replay
                // service drives the worker runtime directly. WASM
                // panic strings can carry user-pasted secrets verbatim
                // (e.g. `panic!("auth failed: sk-... rejected by API")`)
                // and the panic body becomes `e.to_string()` here. Same
                // pattern as MCP-447/527/563/576. Operator-initiated
                // path so the threat model is weaker than user-facing
                // trigger errors, but defense-in-depth is cheap.
                error: Some(talos_dlp_provider::redact_str(&e.to_string())),
            }),
        }
    }
    results
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonrpc_codes_are_stable() {
        assert_eq!(ReplayError::InvalidArg("x".into()).jsonrpc_code(), -32602);
        assert_eq!(ReplayError::NotFound("x".into()).jsonrpc_code(), -32000);
        assert_eq!(
            ReplayError::Internal(anyhow::anyhow!("boom")).jsonrpc_code(),
            -32000,
        );
    }

    #[test]
    fn internal_user_message_does_not_leak_detail() {
        let err = ReplayError::Internal(anyhow::anyhow!(
            "ERROR: column \"output_data_enc\" of relation \"module_executions\" does not exist"
        ));
        // The user-facing message must not echo the underlying
        // anyhow detail — it can leak schema / SQL surface.
        assert_eq!(err.user_facing_message(), "Internal error");
    }

    #[test]
    fn invalid_arg_user_message_passes_through() {
        let err = ReplayError::InvalidArg("limit must be 1..20".into());
        assert_eq!(err.user_facing_message(), "limit must be 1..20");
    }

    #[test]
    fn workflow_plan_rejects_missing_nodes() {
        let graph = serde_json::json!({});
        let err = plan_workflow_replay(&graph, "n1").unwrap_err();
        assert!(matches!(err, ReplayError::InvalidArg(_)));
    }

    #[test]
    fn workflow_plan_rejects_unknown_label() {
        let graph = serde_json::json!({
            "nodes": [{"id": "a", "type": "00000000-0000-0000-0000-000000000001"}],
            "edges": [],
        });
        let err = plan_workflow_replay(&graph, "missing").unwrap_err();
        match err {
            ReplayError::InvalidArg(m) => assert!(m.contains("Available: a"), "msg: {}", m),
            _ => panic!("expected InvalidArg"),
        }
    }

    #[test]
    fn workflow_plan_rejects_fan_in() {
        let graph = serde_json::json!({
            "nodes": [
                {"id": "a", "type": "00000000-0000-0000-0000-000000000001"},
                {"id": "b", "type": "00000000-0000-0000-0000-000000000002"},
                {"id": "c", "type": "00000000-0000-0000-0000-000000000003"},
            ],
            "edges": [
                {"source": "a", "target": "c"},
                {"source": "b", "target": "c"},
            ],
        });
        let err = plan_workflow_replay(&graph, "c").unwrap_err();
        match err {
            ReplayError::InvalidArg(m) => {
                assert!(m.contains("fan-in"), "msg: {}", m);
                assert!(m.contains("2 predecessors"), "msg: {}", m);
            }
            _ => panic!("expected InvalidArg"),
        }
    }

    #[test]
    fn workflow_plan_rejects_invalid_type_uuid() {
        let graph = serde_json::json!({
            "nodes": [{"id": "a", "type": "not-a-uuid"}],
            "edges": [],
        });
        let err = plan_workflow_replay(&graph, "a").unwrap_err();
        match err {
            ReplayError::InvalidArg(m) => assert!(m.contains("type UUID"), "msg: {}", m),
            _ => panic!("expected InvalidArg"),
        }
    }

    #[test]
    fn workflow_plan_root_node_has_no_predecessor() {
        let graph = serde_json::json!({
            "nodes": [{"id": "a", "type": "00000000-0000-0000-0000-000000000001"}],
            "edges": [],
        });
        let plan = plan_workflow_replay(&graph, "a").unwrap();
        assert!(plan.predecessor_label.is_none());
        let expected: Uuid = "00000000-0000-0000-0000-000000000001".parse().unwrap();
        assert_eq!(plan.module_type_id, expected);
        assert!(
            plan.node_config.is_object()
                || plan.node_config.is_null()
                || plan.node_config == serde_json::json!({})
        );
    }

    #[test]
    fn workflow_plan_linear_chain_returns_predecessor() {
        let graph = serde_json::json!({
            "nodes": [
                {"id": "a", "type": "00000000-0000-0000-0000-000000000001",
                 "data": {"foo": 1}},
                {"id": "b", "type": "00000000-0000-0000-0000-000000000002",
                 "data": {"bar": 2}},
            ],
            "edges": [{"source": "a", "target": "b"}],
        });
        let plan = plan_workflow_replay(&graph, "b").unwrap();
        assert_eq!(plan.predecessor_label.as_deref(), Some("a"));
        assert_eq!(plan.node_config, serde_json::json!({"bar": 2}));
    }

    #[test]
    fn workflow_plan_node_config_defaults_when_data_missing() {
        let graph = serde_json::json!({
            "nodes": [{"id": "a", "type": "00000000-0000-0000-0000-000000000001"}],
            "edges": [],
        });
        let plan = plan_workflow_replay(&graph, "a").unwrap();
        assert_eq!(plan.node_config, serde_json::json!({}));
    }

    #[test]
    fn unreplayable_world_blocks_governance_module_mode() {
        let err = reject_unreplayable_world(&CapabilityWorld::Governance, false).unwrap_err();
        match err {
            ReplayError::InvalidArg(m) => {
                assert!(m.contains("governance-node"), "msg: {}", m);
                assert!(m.contains("workflow engine"), "msg: {}", m);
            }
            _ => panic!("expected InvalidArg"),
        }
    }

    #[test]
    fn unreplayable_world_blocks_unknown_workflow_mode() {
        let err = reject_unreplayable_world(&CapabilityWorld::Unknown, true).unwrap_err();
        match err {
            ReplayError::InvalidArg(m) => {
                assert!(m.contains("governance-node"), "msg: {}", m);
                assert!(
                    !m.contains("workflow engine"),
                    "msg should be the shorter workflow-mode form: {}",
                    m
                );
            }
            _ => panic!("expected InvalidArg"),
        }
    }

    #[test]
    fn unreplayable_world_allows_minimal_world() {
        assert!(reject_unreplayable_world(&CapabilityWorld::Minimal, false).is_ok());
        assert!(reject_unreplayable_world(&CapabilityWorld::Minimal, true).is_ok());
    }

    #[test]
    fn unreplayable_world_allows_http_world() {
        assert!(reject_unreplayable_world(&CapabilityWorld::Http, false).is_ok());
    }

    #[test]
    fn ignore_field_set_includes_defaults_and_caller() {
        let extra = ["execution_id".to_string(), "trace_id".to_string()];
        let set = build_ignore_field_set(&extra);
        // Default ignored fields (engine metadata) are baked in. Asserting
        // any one of them is present is enough to verify the chain hooked up.
        let from_defaults: Vec<&str> = DEFAULT_IGNORED_FIELDS.to_vec();
        let probe = from_defaults
            .first()
            .copied()
            .expect("DEFAULT_IGNORED_FIELDS should not be empty — otherwise this test is moot");
        assert!(set.iter().any(|s| s == probe), "missing default {}", probe);
        assert!(set.iter().any(|s| s == "execution_id"));
        assert!(set.iter().any(|s| s == "trace_id"));
    }

    #[test]
    fn ignore_field_set_with_empty_caller_returns_just_defaults() {
        let set = build_ignore_field_set(&[]);
        assert_eq!(set.len(), DEFAULT_IGNORED_FIELDS.len());
    }

    #[test]
    fn count_aggregates_statuses() {
        let row = |s| ReplayResultRow {
            execution_id: Uuid::nil(),
            duration_ms: 0,
            status: s,
            diff: None,
            error: None,
        };
        let rows = vec![
            row(ReplayStatus::Matched),
            row(ReplayStatus::Matched),
            row(ReplayStatus::Drifted),
            row(ReplayStatus::Errored),
        ];
        let c = count(&rows);
        assert_eq!(c.matched, 2);
        assert_eq!(c.drifted, 1);
        assert_eq!(c.errored, 1);
    }

    #[test]
    fn count_zero_when_empty() {
        let c = count(&[]);
        assert_eq!(c.matched, 0);
        assert_eq!(c.drifted, 0);
        assert_eq!(c.errored, 0);
    }
}
