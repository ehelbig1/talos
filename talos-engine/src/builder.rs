//! Controller-side builders for a fully-wired `ParallelWorkflowEngine`.
//!
//! The engine lives in the `talos-workflow-engine` crate and knows nothing
//! about `ModuleRegistry`, `SecretsManager`, or the Talos Postgres
//! adapters. These builders compose those controller-specific pieces
//! into an engine ready for in-tree dispatch.
//!
//! # The canonical builder: `for_workflow`
//!
//! As of r226, `for_workflow` is the canonical entry point for any code
//! that needs to construct an engine and run a workflow against it.
//! Prior to r226 the controller had ~20 ad-hoc engine-construction sites
//! (scheduler, MCP triggers, GraphQL mutations, webhooks, replays,
//! retries, …) — each copying a slightly different subset of setter
//! calls. The drift caused at least one shipped bug (Task #402: scheduler
//! missed `set_execution_timeout_secs`) and surfaced two more in the
//! r226 audit (GraphQL `trigger_workflow` and webhook trigger have the
//! same omission).
//!
//! `for_workflow` accepts an [`EngineOpts`] describing identity,
//! actor context, timeout policy, dry-run, and graph source — and applies
//! them in the right order. See [`EngineOpts::for_run`] and the typed
//! [`TimeoutPolicy`] / [`GraphSource`] enums for the call-site shape.
//!
//! Migration tracking: `docs/engine-builder-refactor-plan.md`.

use serde_json::Value as JsonValue;
use std::sync::Arc;
use talos_workflow_engine::ParallelWorkflowEngine;
use talos_workflow_engine_core::SecretsResolver;
use uuid::Uuid;

use crate::approval_gate::PostgresApprovalGate;
use crate::event_sink::PostgresEventSink;
use crate::expression_evaluator::RhaiEvaluator;
use crate::module_execution_store::PostgresModuleExecutionStore;
use crate::node_hook::ControllerNodeHook;
use crate::retry_classifier::HeuristicRetryClassifier;
use crate::sanitizer::DlpSanitizer;
use talos_actor_repository::ActorRepository;
use talos_oauth::resolver::ControllerSecretsResolver;
use talos_registry::ModuleRegistry;
use talos_secrets_manager::SecretsManager;

/// Build a fully-wired engine from just a `ModuleRegistry` — equivalent
/// to the pre-extraction `ParallelWorkflowEngine::with_registry`.
///
/// **Internal helper — call [`for_workflow`] from dispatch code.**
/// Visibility is `pub(super)` so the door is structurally closed: any
/// future caller outside `engine/` must route through the canonical
/// builder. See module-level docs for why this matters.
#[must_use]
pub(super) fn build_controller_engine_registry_only(
    registry: Arc<ModuleRegistry>,
) -> ParallelWorkflowEngine {
    let pool = registry.db_pool.clone();
    let mut engine = ParallelWorkflowEngine::new();
    engine.set_module_fetcher(registry);
    // Single shared WorkflowRepository instance — the graph_store and
    // sub_actor_context_resolver both wrap it, and the resolver reuses
    // the repo's connection pool / caches for free.
    let workflow_repo = Arc::new(talos_workflow_repository::WorkflowRepository::new(
        pool.clone(),
    ));
    engine.set_graph_store(workflow_repo.clone());
    engine.set_sub_actor_context_resolver(Arc::new(
        crate::sub_actor_context_resolver::ControllerSubActorContextResolver::from_repo(
            workflow_repo,
        ),
    ));
    engine.set_event_sink(Arc::new(PostgresEventSink::new(pool.clone())));
    engine.set_node_hook(Arc::new(ControllerNodeHook::new(pool.clone())));
    engine.set_module_execution_store(Arc::new(PostgresModuleExecutionStore::new(pool.clone())));
    engine.set_ops_alerts_reader(Arc::new(
        crate::ops_alerts_reader::PostgresOpsAlertsReader::new(pool.clone()),
    ));
    engine.set_pending_approvals_reader(Arc::new(
        crate::pending_approvals_reader::PostgresPendingApprovalsReader::new(pool.clone()),
    ));
    engine.set_assistant_report_reader(Arc::new(
        crate::assistant_report_reader::PostgresAssistantReportReader::new(pool.clone()),
    ));
    engine.set_operator_digest_reader(Arc::new(
        crate::operator_digest_reader::PostgresOperatorDigestReader::new(pool.clone()),
    ));
    engine.set_judge_score_recorder(Arc::new(
        crate::judge_score_recorder::PostgresJudgeScoreRecorder::new(pool.clone()),
    ));
    engine.set_approval_gate(Arc::new(PostgresApprovalGate::new(pool)));
    engine.set_expression_evaluator(Arc::new(RhaiEvaluator::new()));
    engine.set_output_sanitizer(Arc::new(DlpSanitizer::new()));
    engine.set_retry_classifier(Arc::new(HeuristicRetryClassifier::new()));
    engine
}

/// Build a fully-wired engine with a pre-built `SecretsResolver` —
/// equivalent to pre-extraction `with_services_and_resolver`.
///
/// **Internal helper — call [`for_workflow`] from dispatch code.**
#[must_use]
pub(super) fn build_controller_engine_with_resolver(
    registry: Arc<ModuleRegistry>,
    secrets_resolver: Arc<dyn SecretsResolver>,
    user_id: Uuid,
) -> ParallelWorkflowEngine {
    let mut engine = build_controller_engine_registry_only(registry);
    engine.set_secrets_resolver(secrets_resolver);
    engine.set_user_id(user_id);
    engine
}

/// Build a fully-wired engine with a `SecretsManager` — equivalent to
/// pre-extraction `with_services`.
///
/// Replaces the plaintext `PostgresModuleExecutionStore` (set by
/// `_registry_only`) with an encryption-aware one wired against the
/// same SecretsManager so module_execution input/output payloads land
/// in `*_enc` columns at rest.
///
/// **Internal helper — call [`for_workflow`] from dispatch code.**
/// `for_workflow` wraps this with the canonical setter sequence
/// (workflow_id, actor identity, actor_context, dry_run, graph load,
/// timeout policy) so dispatch sites can't accidentally drift.
/// Visibility is `pub(super)` so the door is structurally closed.
#[must_use]
pub(super) fn build_controller_engine(
    registry: Arc<ModuleRegistry>,
    secrets_manager: Arc<SecretsManager>,
    user_id: Uuid,
) -> ParallelWorkflowEngine {
    let pool = registry.db_pool.clone();
    let secrets_resolver: Arc<dyn SecretsResolver> =
        Arc::new(ControllerSecretsResolver::new(secrets_manager.clone()));
    let mut engine = build_controller_engine_with_resolver(registry, secrets_resolver, user_id);
    engine.set_module_execution_store(Arc::new(
        PostgresModuleExecutionStore::new(pool.clone()).with_encryption(secrets_manager.clone()),
    ));
    maybe_enable_checkpointing(&mut engine, pool, secrets_manager);
    engine
}

/// Phase C (2026-05-28): opt-in per-node execution checkpointing.
///
/// Off unless `EXECUTION_CHECKPOINTING_ENABLED` is truthy. When on, the
/// TOP-LEVEL engine persists a snapshot of completed-node outputs every
/// `CHECKPOINT_EVERY_N_NODES` (default 1) node completions, so a
/// controller crash / rolling deploy can resume the run from the last
/// checkpoint instead of restarting it. This generalises the existing
/// `Wait`/approval suspend-and-resume to *unplanned* interruptions and is
/// the first step of the durable-execution direction (see
/// docs/rfcs/0003-durable-execution.md).
///
/// Wired ONLY here, in the canonical top-level builder — sub-workflow
/// engines hydrate via `adapter_set().into_engine()`, which deliberately
/// does not carry the store, so children never checkpoint under the
/// parent's `execution_id`.
///
/// Reuses the same `WORKER_SHARED_KEY`-derived AES-256-GCM as the
/// scheduler's completion-time checkpoint, plus the `SecretsManager` for
/// the DEK-column load fallback. If the key is absent the store no-ops on
/// save (logged) — never a hard failure.
fn maybe_enable_checkpointing(
    engine: &mut ParallelWorkflowEngine,
    pool: sqlx::PgPool,
    secrets_manager: Arc<SecretsManager>,
) {
    if !talos_config::bool_env_or_default("EXECUTION_CHECKPOINTING_ENABLED", false) {
        return;
    }
    let every_n = talos_config::get_env("CHECKPOINT_EVERY_N_NODES", "1")
        .parse::<usize>()
        .ok()
        .filter(|n| *n > 0)
        .unwrap_or(1);
    let wsk = talos_workflow_job_protocol::load_worker_shared_key()
        .ok()
        .map(|k| k.as_bytes().to_vec());
    if wsk.is_none() {
        tracing::warn!(
            "EXECUTION_CHECKPOINTING_ENABLED is set but WORKER_SHARED_KEY is unavailable — \
             per-node checkpoint saves will no-op; resume falls back to completion-time \
             checkpoints only"
        );
    }
    let store = crate::checkpoint_store::ControllerCheckpointStore::new(pool, wsk)
        .with_secrets_manager(secrets_manager);
    engine.set_checkpoint_store(Arc::new(store), every_n);
    tracing::info!(
        every_n,
        "per-node execution checkpointing enabled (EXECUTION_CHECKPOINTING_ENABLED)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// `for_workflow` — canonical engine construction for dispatch paths.
// ─────────────────────────────────────────────────────────────────────────────

/// Workflow execution-timeout policy.
///
/// The engine reads `execution_timeout_secs` from the graph JSON during
/// `load_graph_from_json` (see `parse_graph_document` in
/// `talos-workflow-engine/src/engine.rs`). That means any
/// `set_execution_timeout_secs(value)` call BEFORE `load_graph_from_json`
/// is silently overwritten when the graph carries the field. Pre-r226,
/// every dispatch site that thought it was "hardcoding" a timeout (e.g.
/// `test_workflow` with 600 s, secret-rotation verification with 30 s)
/// was actually being overridden by the graph. This enum makes the
/// distinction explicit:
///
/// - [`Honor`](Self::Honor) (default) — let the engine read the graph's
///   value during load, falling back to the engine compile-time default
///   (300 s) if absent.
/// - [`ForceOverride`](Self::ForceOverride) — apply a value AFTER
///   `load_graph_from_json` so it wins over any graph-level field. Use
///   only when the calling path has its own SLA budget.
#[derive(Debug, Clone, Copy)]
pub enum TimeoutPolicy {
    /// Use the engine's built-in handling: parse_graph_document reads
    /// `execution_timeout_secs` from the graph; absence falls back to
    /// the engine compile-time default (300 s).
    Honor,
    /// Force this value AFTER `load_graph_from_json` so it wins over
    /// any graph-level execution_timeout_secs. Use for synchronous
    /// paths that need a tighter SLA than the workflow author chose
    /// (e.g. test_workflow, secret-rotation verification, call_workflow
    /// with caller-supplied `timeout_secs`).
    ForceOverride(u64),
}

/// Source of the workflow graph for engine setup.
///
/// Most dispatch paths pass `Json(graph_json)` and let the engine load.
/// The subworkflow contract service paths use `SkipLoad` and resolve the
/// graph via the engine's `WorkflowGraphStore` after construction.
#[derive(Debug, Clone)]
pub enum GraphSource {
    /// Call `engine.load_graph_from_json(&str)` with this JSON.
    Json(String),
    /// Don't load a graph here; caller will resolve via `WorkflowGraphStore`.
    SkipLoad,
}

/// Build options for [`for_workflow`].
///
/// Construct with [`EngineOpts::for_run`] and refine via the `with_*`
/// methods. Each `with_*` is `mut self` chainable.
#[derive(Debug, Clone)]
pub struct EngineOpts {
    /// The workflow being run. Stamped on the engine via
    /// `set_workflow_id` so analytics rollups in `NodeCompletionContext`
    /// bucket per-workflow rather than per-execution.
    pub workflow_id: Uuid,
    /// Resolved actor identity for this run, or `None` to run anonymously.
    /// The "effective actor" semantics (caller arg falling back to the
    /// workflow's default actor_id) live at the call site — this struct
    /// just takes the resolved value.
    pub effective_actor_id: Option<Uuid>,
    /// Pre-resolved actor memory context to inject into every node's
    /// input as `__actor_context__`. Build via
    /// `talos_memory::actor_context::assemble_payload`.
    pub actor_context: Option<JsonValue>,
    /// See [`TimeoutPolicy`].
    pub timeout: TimeoutPolicy,
    /// If true, dispatched jobs carry `dry_run = true`. The reference
    /// NATS dispatcher mocks side-effecting host functions on dry_run.
    pub dry_run: bool,
    /// See [`GraphSource`].
    pub graph: GraphSource,
}

impl EngineOpts {
    /// Construct opts for a normal workflow run with sensible defaults:
    /// no actor, no actor_context, [`TimeoutPolicy::Honor`], no dry_run.
    #[must_use]
    pub fn for_run(workflow_id: Uuid, graph_json: String) -> Self {
        Self {
            workflow_id,
            effective_actor_id: None,
            actor_context: None,
            timeout: TimeoutPolicy::Honor,
            dry_run: false,
            graph: GraphSource::Json(graph_json),
        }
    }

    /// Construct opts for a workflow run that resolves its graph some other
    /// way — e.g. `execute_subworkflow_graph` (uses `WorkflowGraphStore`)
    /// or programmatic node assembly via `engine.add_node` / `add_edge`.
    ///
    /// Equivalent to `for_run(workflow_id, String::new()).with_skip_graph_load()`
    /// but expresses intent at the call site without the dummy empty string.
    #[must_use]
    pub fn for_skip_load(workflow_id: Uuid) -> Self {
        Self {
            workflow_id,
            effective_actor_id: None,
            actor_context: None,
            timeout: TimeoutPolicy::Honor,
            dry_run: false,
            graph: GraphSource::SkipLoad,
        }
    }

    /// Apply the "effective actor" pattern: caller-supplied `arg` wins,
    /// falling back to the workflow's default `actor_id`. Either or both
    /// may be `None`.
    #[must_use]
    pub fn with_effective_actor(
        mut self,
        arg: Option<Uuid>,
        workflow_default: Option<Uuid>,
    ) -> Self {
        self.effective_actor_id = arg.or(workflow_default);
        self
    }

    /// Bind a specific actor unconditionally. Use for paths like
    /// `handoff_to_actor` where the actor identity is required and the
    /// "effective" fallback doesn't apply.
    #[must_use]
    pub fn with_actor_id(mut self, actor_id: Uuid) -> Self {
        self.effective_actor_id = Some(actor_id);
        self
    }

    /// Inject pre-resolved actor memory context. Pass `None` to keep
    /// whatever the engine's default is (no injection).
    #[must_use]
    pub fn with_actor_context(mut self, ctx: Option<JsonValue>) -> Self {
        self.actor_context = ctx;
        self
    }

    /// Set the dry-run flag.
    #[must_use]
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Force a timeout that wins over the graph's value. See
    /// [`TimeoutPolicy::ForceOverride`].
    #[must_use]
    pub fn with_timeout_override(mut self, secs: u64) -> Self {
        self.timeout = TimeoutPolicy::ForceOverride(secs);
        self
    }

    /// Skip graph loading. Use for sub-workflow dispatch paths where
    /// the engine resolves the graph via `WorkflowGraphStore` later.
    // Reserved for the sub-workflow-resolves-graph paths once they
    // adopt the builder. Currently not invoked by any caller.
    #[allow(dead_code)]
    #[must_use]
    pub fn with_skip_graph_load(mut self) -> Self {
        self.graph = GraphSource::SkipLoad;
        self
    }
}

/// Failure modes from [`for_workflow`].
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// `load_graph_from_json` failed. Carries the typed engine error so
    /// callers can use [`crate::user_errors::render_graph_load_error`]
    /// to produce the same human-readable message they would have gotten
    /// from calling `load_graph_from_json` directly.
    #[error("graph load failed: {0}")]
    GraphLoad(#[from] talos_workflow_engine::WorkflowEngineError),
}

/// Build a fully-wired engine ready for dispatch from [`EngineOpts`].
///
/// Order of operations (matters because `load_graph_from_json` overwrites
/// the timeout field from the graph JSON):
/// 1. `build_controller_engine` (registry, secrets, user_id wiring)
/// 2. `set_workflow_id`
/// 3. `apply_actor_to_engine` if `effective_actor_id` is set — fail-closed
///    on Err (helper stamps Tier1 + logs; we log + continue)
/// 4. `set_actor_context` if `actor_context` is set
/// 5. `set_dry_run` if `dry_run = true`
/// 6. `load_graph_from_json` (this is when the engine reads
///    `execution_timeout_secs` from the JSON)
/// 7. Apply `TimeoutPolicy::ForceOverride` AFTER load so it wins over
///    the graph's value
///
/// **Security contract**: step 3 swallows the actor-resolution error
/// because `apply_actor_to_engine` already stamped Tier1 internally
/// before returning Err. A future maintainer who "fixes" this by
/// bubbling the error would break the fail-closed tier-1 enforcement.
/// Keep the swallow.
pub async fn for_workflow(
    registry: Arc<ModuleRegistry>,
    secrets_manager: Arc<SecretsManager>,
    actor_repo: Arc<ActorRepository>,
    user_id: Uuid,
    opts: EngineOpts,
) -> Result<ParallelWorkflowEngine, BuildError> {
    // Capture the pool before `registry` is moved into the engine builder —
    // needed for the adaptive-fuel history lookup below.
    let pool = registry.db_pool.clone();

    // 1. Base engine.
    let mut engine = build_controller_engine(registry, secrets_manager, user_id);

    // 2. Workflow id (analytics rollups).
    engine.set_workflow_id(opts.workflow_id);

    // 2b. Adaptive fuel (Phase 2): raise per-node ceilings toward observed
    //     demand so a node never silently under-provisions. GUARD MODE — the
    //     learned value is applied as a floor by `resolve_node_max_fuel`, so it
    //     can only RAISE a ceiling, never lower a deliberately-set one, and can
    //     never introduce a fuel failure the static ceiling wouldn't have had.
    //     Fail-open + cached; kill switch `TALOS_ADAPTIVE_FUEL=0`.
    let learned = crate::adaptive_fuel::learned_fuel_ceilings(&pool, opts.workflow_id).await;
    if !learned.is_empty() {
        // INFO so operators see adaptation in the logs without querying the
        // rollup. Fires once per engine build (per execution) when any node has
        // ≥5 samples; `ceilings` carries the learned value per node label.
        // Guard mode means each is a floor, so a node is only actually raised
        // when its learned value exceeds its configured baseline at dispatch.
        tracing::info!(
            workflow_id = %opts.workflow_id,
            nodes = learned.len(),
            ceilings = ?learned,
            "adaptive fuel: loaded learned per-node ceilings (guard mode — raises only)"
        );
        engine.set_learned_fuel_ceilings(learned);
    }

    // 3. Actor identity. The helper stamps Tier1 fail-closed on error,
    //    so we log + continue; bubbling would defeat the fail-closed
    //    contract by giving the caller "no actor at all" instead of
    //    "actor with safe ceiling".
    if let Some(actor_id) = opts.effective_actor_id {
        if let Err(e) =
            crate::actor_binding::apply_actor_to_engine(&actor_repo, &mut engine, actor_id).await
        {
            tracing::warn!(
                workflow_id = %opts.workflow_id,
                %actor_id,
                error = %e,
                "engine_builder::for_workflow: apply_actor_to_engine failed; engine stamped Tier1 for safety"
            );
        }
    }

    // 4. Actor context.
    if let Some(ctx) = opts.actor_context {
        engine.set_actor_context(ctx);
    }

    // 5. Dry-run flag (load doesn't touch this field).
    if opts.dry_run {
        engine.set_dry_run(true);
    }

    // 6. Load graph (engine reads `execution_timeout_secs` from JSON here
    //    via `parse_graph_document`).
    if let GraphSource::Json(json) = &opts.graph {
        engine.load_graph_from_json(json).await?;
    }

    // 7. Apply override AFTER load so it wins.
    if let TimeoutPolicy::ForceOverride(secs) = opts.timeout {
        engine.set_execution_timeout_secs(secs);
    }

    Ok(engine)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for the EngineOpts builder methods. Tests against `for_workflow`
// itself live in `controller/tests/engine_builder_tests.rs` — they need a
// `ModuleRegistry` and `ActorRepository`, which need a Postgres pool.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod opts_tests {
    use super::*;

    fn wf() -> Uuid {
        Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
    }
    fn arg_actor() -> Uuid {
        Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
    }
    fn wf_actor() -> Uuid {
        Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()
    }

    #[test]
    fn for_run_defaults_match_documented_contract() {
        let opts = EngineOpts::for_run(wf(), "{}".to_string());
        assert_eq!(opts.workflow_id, wf());
        assert!(opts.effective_actor_id.is_none());
        assert!(opts.actor_context.is_none());
        assert!(matches!(opts.timeout, TimeoutPolicy::Honor));
        assert!(!opts.dry_run);
        assert!(matches!(opts.graph, GraphSource::Json(_)));
    }

    #[test]
    fn effective_actor_arg_wins_over_workflow_default() {
        let opts = EngineOpts::for_run(wf(), "{}".to_string())
            .with_effective_actor(Some(arg_actor()), Some(wf_actor()));
        assert_eq!(opts.effective_actor_id, Some(arg_actor()));
    }

    #[test]
    fn effective_actor_falls_back_to_workflow_default() {
        let opts = EngineOpts::for_run(wf(), "{}".to_string())
            .with_effective_actor(None, Some(wf_actor()));
        assert_eq!(opts.effective_actor_id, Some(wf_actor()));
    }

    #[test]
    fn effective_actor_both_none_stays_none() {
        let opts = EngineOpts::for_run(wf(), "{}".to_string()).with_effective_actor(None, None);
        assert!(opts.effective_actor_id.is_none());
    }

    #[test]
    fn with_actor_id_sets_unconditionally() {
        // Even though the existing field is None, with_actor_id sets it.
        // Used by handoff_to_actor where actor identity is required.
        let opts = EngineOpts::for_run(wf(), "{}".to_string()).with_actor_id(arg_actor());
        assert_eq!(opts.effective_actor_id, Some(arg_actor()));
    }

    #[test]
    fn with_timeout_override_replaces_honor() {
        let opts = EngineOpts::for_run(wf(), "{}".to_string()).with_timeout_override(60);
        match opts.timeout {
            TimeoutPolicy::ForceOverride(60) => {}
            other => panic!("expected ForceOverride(60), got {other:?}"),
        }
    }

    #[test]
    fn with_dry_run_toggles_flag() {
        let opts = EngineOpts::for_run(wf(), "{}".to_string()).with_dry_run(true);
        assert!(opts.dry_run);
    }

    #[test]
    fn with_actor_context_some_sets_it() {
        let ctx = serde_json::json!({"actor_id": "x"});
        let opts =
            EngineOpts::for_run(wf(), "{}".to_string()).with_actor_context(Some(ctx.clone()));
        assert_eq!(opts.actor_context, Some(ctx));
    }

    #[test]
    fn with_actor_context_none_stays_none() {
        let opts = EngineOpts::for_run(wf(), "{}".to_string()).with_actor_context(None);
        assert!(opts.actor_context.is_none());
    }

    #[test]
    fn with_skip_graph_load_replaces_json_variant() {
        let opts = EngineOpts::for_run(wf(), "{\"nodes\":[]}".to_string()).with_skip_graph_load();
        assert!(matches!(opts.graph, GraphSource::SkipLoad));
    }

    #[test]
    fn for_skip_load_starts_with_skip_load_variant() {
        let opts = EngineOpts::for_skip_load(wf());
        assert_eq!(opts.workflow_id, wf());
        assert!(matches!(opts.graph, GraphSource::SkipLoad));
        assert!(opts.effective_actor_id.is_none());
        assert!(opts.actor_context.is_none());
        assert!(matches!(opts.timeout, TimeoutPolicy::Honor));
        assert!(!opts.dry_run);
    }
}
