#![allow(dead_code)]

use futures::stream::{FuturesUnordered, StreamExt};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use serde_json::Value as JsonValue;
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{LazyLock, OnceLock};

/// Wrap a scheduler future in the workflow-level wall-clock cap and
/// produce the typed [`crate::WorkflowEngineError`] result.
///
/// Lifted out of `run_inner` so the timeout sentinel can be
/// constructed with the configured `secs` value directly, matching
/// the [`crate::WorkflowEngineError::Timeout`] variant's contract,
/// without forcing the inner reactor body to thread a typed error.
///
/// `secs == 0` opts out of the wall-clock cap entirely (per-node
/// timeouts remain the only safety net). Non-zero wraps with
/// [`tokio::time::timeout`].
async fn run_with_workflow_timeout(
    secs: u64,
    cancel: Option<tokio_util::sync::CancellationToken>,
    fut: impl std::future::Future<Output = Result<talos_workflow_engine_core::WorkflowContext, String>>,
) -> Result<talos_workflow_engine_core::WorkflowContext, crate::WorkflowEngineError> {
    // Race the inner scheduler against:
    // 1. The optional caller-supplied cancellation token (returns
    //    `WorkflowEngineError::Cancelled`).
    // 2. The workflow-level wall-clock cap (returns `Timeout`).
    // 3. The inner scheduler's own completion (returns its result).
    //
    // `tokio::pin!` keeps the future on the stack so it can be polled
    // from within `select!` without needing `Box::pin`. The cancel
    // branch is only enabled when a token was provided — using
    // `if let Some(...)` inside `select!` would require pre-cloning
    // the token, so we branch above instead.
    tokio::pin!(fut);
    let timeout_dur = (secs > 0).then(|| std::time::Duration::from_secs(secs));

    let inner_result: Result<Result<_, String>, ()> = match (cancel, timeout_dur) {
        (Some(token), Some(dur)) => tokio::select! {
            biased; // honour cancellation before timeout if both fire same tick
            () = token.cancelled() => return Err(crate::WorkflowEngineError::Cancelled),
            r = tokio::time::timeout(dur, &mut fut) => match r {
                Ok(inner) => Ok(inner),
                Err(_) => return Err(crate::WorkflowEngineError::Timeout { secs }),
            },
        },
        (Some(token), None) => tokio::select! {
            biased;
            () = token.cancelled() => return Err(crate::WorkflowEngineError::Cancelled),
            inner = &mut fut => Ok(inner),
        },
        (None, Some(dur)) => match tokio::time::timeout(dur, fut).await {
            Ok(inner) => Ok(inner),
            Err(_) => return Err(crate::WorkflowEngineError::Timeout { secs }),
        },
        (None, None) => Ok(fut.await),
    };
    match inner_result {
        Ok(Ok(ctx)) => Ok(ctx),
        Ok(Err(e)) => Err(crate::WorkflowEngineError::execution(e)),
        // Unreachable in practice — the early returns above cover
        // both cancel + timeout. Kept so the match is exhaustive.
        Err(()) => Err(crate::WorkflowEngineError::Cancelled),
    }
}

/// Process-global per-module rate-limit counter:
/// `module_id -> (window_start, request_count)`.
///
/// **Why global?** Rate limits are typically capacity guards for the
/// underlying *resource* (an LLM provider key, a downstream API
/// quota), not the workflow run that touches it. A single key with
/// `60 RPM` should still be capped at 60 RPM whether one workflow or
/// twenty hit it concurrently. Per-engine state would let a sharded
/// fleet trivially exceed the cap by spreading dispatches across
/// instances.
///
/// **Lifecycle.** Entries are inserted by [`check_rate_limit`] on the
/// first dispatch for a given module and rolled over on each 60-
/// second window boundary. Stale entries are pruned by a background
/// tokio task spawned idempotently from
/// [`ensure_rate_limit_eviction_task`] — every
/// [`RATE_LIMIT_EVICTION_INTERVAL_SECS`] (60 s) it runs
/// [`evict_stale_rate_limits`], which prunes entries older than
/// [`RATE_LIMIT_STALE_SECS`] (≥ 300 s) when the map exceeds
/// [`RATE_LIMIT_MAX_ENTRIES`] (1 000). The map is process-static —
/// there is no runtime way to drop it short of restarting the
/// process or calling [`reset_global_rate_limits`].
///
/// **Test isolation.** Tests that depend on counter values use
/// [`reset_global_rate_limits`] between cases. Without this, a test
/// that exercises the limit will leave the counter populated for the
/// next test in the binary's run.
///
/// **Wanting per-engine instead?** Use a `NodeDispatcher` impl that
/// tracks its own counters — the engine's check is a guardrail, not
/// the only enforcement layer. The engine-level enforcement is
/// process-global by design and a downstream limiter is the right
/// place for tenant-scoped or worker-pool-scoped variants.
pub(crate) static MODULE_RATE_LIMITS: LazyLock<
    dashmap::DashMap<uuid::Uuid, (std::time::Instant, u32)>,
> = LazyLock::new(dashmap::DashMap::new);

/// Clear the process-global per-module rate-limit counters.
///
/// Use in tests that exercise the limit (and in long-lived tools that
/// want to reset metering after a configuration reload). Production
/// engines should not call this — it disables the rate-limit
/// guarantees for any in-flight workflow until the counter
/// reaccumulates.
pub fn reset_global_rate_limits() {
    MODULE_RATE_LIMITS.clear();
}

/// Number of entries currently held in the process-global rate-limit
/// counter. Useful for tests and observability tooling that needs to
/// confirm eviction is keeping the map bounded.
#[must_use]
pub fn global_rate_limit_entry_count() -> usize {
    MODULE_RATE_LIMITS.len()
}

/// Default per-node execution timeout (in seconds) applied when a node's
/// graph data doesn't carry an explicit `timeout_secs`.
///
/// 120s is the controller's reply-wait for a node's worker job. It MUST be
/// >= the worker's own maximum per-operation budget, or the controller abandons
/// a node that is still legitimately working: the worker allows up to
/// `EXTERNAL_LLM_EXCHANGE_TIMEOUT_SECS` (120s) for an external LLM exchange,
/// `MAX_HTTP_TIMEOUT_MS` (120s) for a single `http::fetch`, and 60s for a local
/// Ollama exchange — and a single module commonly chains several (e.g.
/// github-pr-reviewer does HTTP diff fetch + LLM review + HTTP comment post).
/// The previous 60s default was shorter than even one external-LLM/HTTP op, so a
/// slow-but-valid node (large diff + slow/CPU-bound model) was dropped mid-flight
/// while the worker kept running — wasting the work and stranding the execution.
/// 120s matches the worker's single-op ceiling and still covers the common chain.
/// Individual nodes can still raise or lower via
/// `add_node_to_workflow(timeout_secs:…)`; there is no implicit clamp.
///
/// Respects `WASM_EXECUTION_TIMEOUT_SECS` env var for operator override —
/// matches `get_wasm_config`'s default so the tool output and actual
/// runtime behavior agree.
pub static DEFAULT_NODE_TIMEOUT_SECS: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("WASM_EXECUTION_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(120)
});

/// M5 (2026-05-28 review): maximum number of node-dispatch futures the reactor
/// keeps in flight at once (the `executing` pool: regular module nodes +
/// pipeline-chain heads). Without a ceiling, a wide fan-out — a diamond / many
/// parallel branches — drained the whole `ready` queue and pushed EVERY branch's
/// NATS job into the pool simultaneously, and recursive sub-workflows multiplied
/// it, saturating the worker fleet / NATS in-flight cap. The reactor now stops
/// pulling from `ready` once the pool reaches this size and resumes as futures
/// complete (backpressure), which throttles dispatch without changing any
/// observable result or ordering. The historical doc note said "8 is enough for
/// typical fan-out"; that is the default. Override via `TALOS_MAX_CONCURRENT_NODES`.
pub(crate) const DEFAULT_MAX_CONCURRENT_NODE_DISPATCH: usize = 8;

/// Resolved `TALOS_MAX_CONCURRENT_NODES` (see
/// [`DEFAULT_MAX_CONCURRENT_NODE_DISPATCH`]). Clamped to `>= 1` so a `0` /
/// negative / unparseable value can never wedge the reactor (a cap of 0 would
/// never dispatch anything).
pub(crate) static MAX_CONCURRENT_NODE_DISPATCH: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("TALOS_MAX_CONCURRENT_NODES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(DEFAULT_MAX_CONCURRENT_NODE_DISPATCH)
});

/// Maximum entries the rate-limit counter retains before eviction
/// kicks in. Tuned to be cheap to scan (`DashMap::retain` over ≤ 1000
/// shards-worth of entries is sub-millisecond) while still letting a
/// burst of distinct module ids accumulate without thrashing.
const RATE_LIMIT_MAX_ENTRIES: usize = 1000;

/// Window after which a stale rate-limit entry is eligible for
/// eviction. Five minutes is well past the 60-second metering window
/// the limiter itself uses, so a recently-active module never gets
/// pruned mid-window.
const RATE_LIMIT_STALE_SECS: u64 = 300;

/// How often the background eviction task wakes up to scan
/// [`MODULE_RATE_LIMITS`]. 60 seconds matches the metering window —
/// at most one scan per window is enough to keep the map bounded
/// even under steady-state burst.
const RATE_LIMIT_EVICTION_INTERVAL_SECS: u64 = 60;

/// Evict stale entries from [`MODULE_RATE_LIMITS`] when the map grows
/// beyond [`RATE_LIMIT_MAX_ENTRIES`].
///
/// Lifted out of the hot path (used to run inline on every
/// `check_rate_limit` invocation, even when the map was tiny). Now
/// invoked from the background task spawned by
/// [`ensure_rate_limit_eviction_task`]. Leaving the function `pub(crate)`
/// + free for tests that want to force an immediate scan.
pub(crate) fn evict_stale_rate_limits() {
    if MODULE_RATE_LIMITS.len() > RATE_LIMIT_MAX_ENTRIES {
        let cutoff =
            std::time::Instant::now() - std::time::Duration::from_secs(RATE_LIMIT_STALE_SECS);
        MODULE_RATE_LIMITS.retain(|_, (window_start, _)| *window_start > cutoff);
    }
}

/// Spawn the background eviction task on first invocation of
/// [`check_rate_limit`].
///
/// The task lives for the lifetime of the process — `OnceLock` makes
/// it idempotent across concurrent first-callers. Each tick wakes
/// after [`RATE_LIMIT_EVICTION_INTERVAL_SECS`] and runs
/// [`evict_stale_rate_limits`].
///
/// **Why first-use lazy spawn?** The eviction task needs a tokio
/// runtime, and the engine's `check_rate_limit` path is only ever
/// reached from inside `run_with_transport` /
/// `run_with_seed_with_transport` — both `async fn`s, both called
/// from a tokio context by definition. Spawning at module-load time
/// would panic for consumers that pull in `talos-workflow-engine`
/// without a runtime (test-only paths, doc examples, etc.).
pub(crate) fn ensure_rate_limit_eviction_task() {
    static SPAWN_GUARD: OnceLock<()> = OnceLock::new();
    SPAWN_GUARD.get_or_init(|| {
        tokio::spawn(async {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(
                RATE_LIMIT_EVICTION_INTERVAL_SECS,
            ));
            // First tick fires immediately; skip it so the very first
            // scan happens after one full interval rather than at
            // task start (when the map is guaranteed near-empty).
            tick.tick().await;
            loop {
                tick.tick().await;
                evict_stale_rate_limits();
            }
        });
    });
}

// Alias to silence Clippy's `type_complexity` warning and improve readability.
// Represents a boxed future that resolves to a node index and its execution result.
// Generic alias allowing the future to live for any lifetime `'a`.
type ExecFuture<'a> =
    Pin<Box<dyn Future<Output = (NodeIndex, Result<JsonValue, String>)> + Send + 'a>>;
use std::sync::Arc;
use uuid::Uuid;

/// Default for [`ParallelWorkflowEngine::max_prefetch_successors`] —
/// the upper bound on successor nodes the engine will speculatively
/// prefetch when a node opts in via `speculative_prefetch: true`.
///
/// 8 is enough for typical fan-out shapes (a few branches per node)
/// without giving a pathological 1-to-N graph an easy `DoS` vector.
/// Override per-engine via
/// [`ParallelWorkflowEngine::set_max_prefetch_successors`].
pub const DEFAULT_MAX_PREFETCH_SUCCESSORS: usize = 8;

/// Default for [`ParallelWorkflowEngine::max_workflow_nodes`] — the
/// hard cap on `add_node` calls per engine instance. Prevents a
/// malformed or adversarial graph from exhausting memory before
/// dispatch starts.
///
/// 500 is well above any reasonable hand-authored workflow but small
/// enough to make a runaway code-gen path obvious. Override per-engine
/// via [`ParallelWorkflowEngine::set_max_workflow_nodes`].
pub const DEFAULT_MAX_WORKFLOW_NODES: usize = 500;

/// Default for [`ParallelWorkflowEngine::max_node_output_bytes`] — the
/// per-node output size guard. Outputs over this limit get replaced
/// with an `__error: true` envelope so the result map / accumulated
/// snapshot can't blow up downstream.
///
/// 5 MiB covers every shape we've observed in production; larger
/// outputs are almost always a bug (stringified binary, unfiltered
/// query result, etc.). Override per-engine via
/// [`ParallelWorkflowEngine::set_max_node_output_bytes`].
pub const DEFAULT_MAX_NODE_OUTPUT_BYTES: usize = 5 * 1024 * 1024;

/// Default for [`ParallelWorkflowEngine::max_fuel_per_node`] — the
/// upper bound on Wasmtime fuel granted to any single dispatch.
///
/// Caps both per-node fuel overrides from the graph JSON and the
/// module's declared fuel budget; a malicious or careless module
/// can't request unbounded compute time. 50M corresponds to ~5 s of
/// dense numeric work on the reference worker; HTTP-bound and LLM
/// modules use a tiny fraction of this. Override per-engine via
/// [`ParallelWorkflowEngine::set_max_fuel_per_node`].
pub const DEFAULT_MAX_FUEL_PER_NODE: u64 = 50_000_000;

/// Default for [`ParallelWorkflowEngine::agent_loop_max_history`] —
/// the maximum number of prior-iteration outputs injected as
/// `__agent_history__` on each `AgentLoop` / `ReActLoop` body
/// invocation.
///
/// 20 is the calibrated default for `ReAct` chains with ~5 KiB outputs
/// per step (the engine's typical workload). Larger windows raise per-
/// iteration context cost; shorter windows lose context. Override per-
/// engine with [`ParallelWorkflowEngine::set_agent_loop_max_history`].
pub const DEFAULT_AGENT_LOOP_MAX_HISTORY: usize = 20;

/// Default for [`ParallelWorkflowEngine::max_subflow_depth`] — the
/// recursion-depth ceiling for sub-workflow dispatch.
///
/// Every sub-workflow handler hydrates a child engine via
/// [`AdapterSet::into_engine_with_graph`]; that path increments the
/// dispatch depth. A workflow that transitively references itself —
/// or a sufficiently deep composition graph — would stack-overflow
/// the reactor without this cap.
///
/// 16 is well above any hand-authored composition (deepest patterns
/// observed in production are ~5: `AgentLoop` body containing a
/// `Judge` whose rubric runs a sub-workflow). Override per-engine
/// via [`ParallelWorkflowEngine::set_max_subflow_depth`].
pub const DEFAULT_MAX_SUBFLOW_DEPTH: usize = 16;

use crate::emit_event_spawn;
use talos_workflow_engine_core::{
    CheckpointStore, EdgeLogic, EventSink, ModuleFetcher, NodeEventWrite, NodeLifecycleHook,
    SecretsResolver, SystemNodeKind, WorkflowContext, WorkflowGraphStore,
};

/// Opt-in per-node checkpointing config (Phase C, 2026-05-28). When the
/// controller wires a [`CheckpointStore`] onto the TOP-LEVEL engine, each
/// node completion debounce-persists a snapshot of all completed-node
/// outputs so an interrupted run (controller crash / rolling deploy) can
/// resume from the last persisted node instead of restarting from scratch
/// — generalising the existing `Wait`/approval suspend-and-resume to
/// cover *unplanned* interruptions.
///
/// Reliability of the "top-level only" boundary comes from construction,
/// not a depth check: [`AdapterSet`] (the sole engine→sub-workflow
/// propagation path, see [`ParallelWorkflowEngine::adapter_set`]) does NOT
/// carry this field, and sub-engines build from [`ParallelWorkflowEngine::new`]
/// (where it is `None`). So a child engine can never inherit a parent's
/// store, and sub-workflow runs never write checkpoints under the parent's
/// `execution_id`.
pub(crate) struct CheckpointConfig {
    /// Consumer-provided store; owns encryption + persistence. The engine
    /// only hands it plaintext `JsonValue` snapshots.
    pub(crate) store: Arc<dyn CheckpointStore>,
    /// Persist on every `every_n`-th node completion. `0` disables (treated
    /// as "no checkpointing" even if a store is present). Larger values
    /// trade resume granularity (more nodes re-run after a crash) for less
    /// re-encryption work on big graphs.
    pub(crate) every_n: usize,
    /// Node-completion counter (interior mutability — the completion
    /// handler is `&self`). Fresh per engine instance.
    pub(crate) dirty: std::sync::atomic::AtomicUsize,
}

// Checkpoint encryption + persistence is the responsibility of the
// consumer's `CheckpointStore` impl (see
// `talos_workflow_engine_core::CheckpointStore`). The engine itself
// holds only an `Arc<dyn CheckpointStore>` and never talks to a
// database directly.

#[allow(deprecated)]
pub use crate::sandbox::DEFAULT_SANDBOX_ROOT;
use crate::sandbox::{create_execution_sandbox, SandboxGuard};
pub use crate::sandbox::{default_sandbox_root, DEFAULT_SANDBOX_DIR_NAME};
use crate::secrets_pipeline::{build_encrypted_secrets_for, extract_vault_paths};
// `sanitize_node_output` is used by `engine_completion::handle_node_success`
// (the post-completion path). Re-imported there because the helper moved
// out of this file; left without a use here so we don't pull a now-unused
// import.

pub(crate) use crate::chain_detect::detect_linear_chains;

// Canonical LLM provider vault paths live in `talos_workflow_job_protocol::LLM_PROVIDER_VAULT_PATHS`.
// Import from there directly — this crate no longer re-exports to keep one
// single source of truth discoverable by `grep LLM_PROVIDER_VAULT_PATHS`.
// LLM-key pre-fetch flows through `SecretsResolver::resolve_llm_keys`.
// Consumers implement the trait to delegate to their own secrets backend.

#[cfg(test)]
pub(crate) use crate::engine_dispatch_subflow::extract_judge_score;
pub use crate::engine_dispatch_subflow::{JudgeVerdict, SubflowError};

// Suppress dead‑code warnings to keep the CI passing.
#[allow(dead_code)]
/// Parallel execution engine based on Kahn's algorithm.
///
/// # Accessing internal state
///
/// Read access to the engine's graph, node metadata, and per-node
/// configuration goes through accessor methods — [`graph`](Self::graph),
/// [`node_map`](Self::node_map), [`node_labels`](Self::node_labels),
/// [`node_configs`](Self::node_configs), [`node_meta`](Self::node_meta),
/// [`execution_timeout_secs`](Self::execution_timeout_secs), and
/// [`dry_run`](Self::dry_run). Write access uses the dedicated
/// setters ([`set_user_id`](Self::set_user_id),
/// [`set_execution_timeout_secs`](Self::set_execution_timeout_secs),
/// [`set_dry_run`](Self::set_dry_run), etc.). The underlying fields
/// are `pub(crate)` — not part of the public API surface.
pub struct ParallelWorkflowEngine {
    pub(crate) graph: DiGraph<Uuid, EdgeLogic>,
    pub(crate) node_map: HashMap<Uuid, NodeIndex>,
    /// Maps internal node UUIDs back to user-defined node IDs (e.g., "n1", "fetch").
    /// Populated by `load_graph_from_json`. Used to label output with user-friendly keys.
    pub(crate) node_labels: HashMap<Uuid, String>,
    /// Per-node configuration from the workflow graph. Merged into the module
    /// config when dispatching jobs, so template modules receive the config
    /// the user specified at workflow creation time.
    pub(crate) node_configs: HashMap<Uuid, serde_json::Value>,
    /// Pluggable resolver for the wasm module artifact that a node dispatches.
    /// In production wraps [`ModuleRegistry`] (which owns the 4-level fallback
    /// pipeline). Tests and out-of-tree consumers plug in their own impl.
    pub(crate) module_fetcher: Option<Arc<dyn ModuleFetcher>>,
    /// Pluggable fire-and-forget sink for per-node execution events
    /// (`node_started`, `node_completed`, `node_failed`, retries, loop
    /// iterations, etc.). In production wraps `execution_events` table
    /// writes; tests can plug in a no-op or in-memory capture.
    pub(crate) event_sink: Option<Arc<dyn EventSink>>,
    /// Post-completion hook invoked after each node finalizes its
    /// output. In production drives fuel-cost attribution and the
    /// `__memory_write__` actor-memory protocol; tests can plug in a
    /// capture hook to assert per-node outputs.
    pub(crate) node_hook: Option<Arc<dyn NodeLifecycleHook>>,
    /// Opt-in per-node checkpointing (Phase C). `None` (the default, and
    /// the value on every sub-workflow engine) = exactly today's
    /// behaviour. Set only on the top-level engine by the controller when
    /// `EXECUTION_CHECKPOINTING_ENABLED` is on. Deliberately NOT carried by
    /// [`AdapterSet`], so sub-engines never inherit it.
    pub(crate) checkpoint: Option<CheckpointConfig>,
    /// Pluggable read-only access to workflow graph definitions — used
    /// when the engine hits a sub-workflow-ish system node (sub-workflow,
    /// judge, ensemble child, agent-loop body, reflective-retry child,
    /// LLM-dispatch route, etc.) and needs to hydrate its body's
    /// `graph_json`. In production wraps `WorkflowRepository`.
    pub(crate) graph_store: Option<Arc<dyn WorkflowGraphStore>>,
    /// Pluggable resolver that hands the engine the `__actor_context__`
    /// payload for a sub-workflow about to be dispatched. Lets sub-workflows
    /// bound to a different actor than the parent inherit their OWN actor's
    /// memories under `__actor_context__` instead of running with no
    /// context. When `None` (the default), sub-workflows behave as before:
    /// no engine-set context, `INJECT_CONTEXT` degrades to whatever the
    /// trigger input happens to carry. See
    /// [`talos_workflow_engine_core::SubworkflowActorContextResolver`].
    pub(crate) sub_actor_context_resolver:
        Option<Arc<dyn talos_workflow_engine_core::SubworkflowActorContextResolver>>,
    /// Pluggable secret resolver. All module-secret, vault-path, and LLM-key
    /// lookups — plus the pre-resolution OAuth refresh hook — flow through
    /// this trait object, which in production wraps a `SecretsManager`.
    /// Tests and out-of-tree consumers plug in their own implementation.
    pub(crate) secrets_resolver: Option<Arc<dyn SecretsResolver>>,
    /// Owner of the workflow execution — required to enforce module ownership
    /// when fetching WASM bytes/config from the registry. `None` means the
    /// engine is running in a test/fallback context without a real registry.
    pub(crate) user_id: Option<Uuid>,
    /// Per-node metadata: maps node UUID to (`module_id`, `retry_policy`, kind).
    pub(crate) node_meta: HashMap<
        Uuid,
        (
            Option<Uuid>,
            Option<talos_workflow_engine_core::RetryPolicy>,
            Option<SystemNodeKind>,
        ),
    >,
    /// Maximum execution time for the entire workflow in seconds. Default: 300 (5 minutes).
    pub(crate) execution_timeout_secs: u64,
    /// Per-module rate limits (requests per minute), loaded at graph init time.
    pub(crate) rate_limits: HashMap<Uuid, i32>,
    /// Per-node execution timeout in seconds. Overrides the default 30-second timeout.
    /// Loaded from `node.data.timeout_secs` or `node.timeout_secs` in the graph JSON.
    pub(crate) node_timeouts: HashMap<Uuid, u64>,
    /// Actor ID that owns this execution — used for __`memory_write`__ write-back.
    pub(crate) actor_id: Option<Uuid>,
    /// Actor memory context injected into every node's input as `__actor_context__`.
    /// Populated by the scheduler or `trigger_workflow` when an actor owns the execution.
    /// Enables LLM nodes to reference `learned_preferences`, persona, and other actor
    /// state without per-workflow plumbing.
    pub(crate) actor_context: Option<serde_json::Value>,
    /// Speculative module prefetch cache — populated by background fetch tasks when a node
    /// has `speculative_prefetch: true`. `fetch_module` checks here first to avoid a DB
    /// round-trip when the module was pre-loaded while a slow predecessor was executing.
    pub(crate) module_prefetch_cache:
        Arc<dashmap::DashMap<Uuid, talos_workflow_engine_core::WasmModuleArtifact>>,
    /// Per-execution module-artifact cache, keyed by **resolved `module_id`**.
    ///
    /// Module bytes (and the rest of [`WasmModuleArtifact`]) are run-invariant:
    /// a workflow that reuses the same module across M nodes / branches would
    /// otherwise issue M identical full-`wasm_bytes`-blob SELECTs against
    /// Postgres per run (see `talos_registry::Registry::get_module`). This cache
    /// memoizes the fetched artifact for the lifetime of THIS engine instance so
    /// the blob is loaded at most once per distinct module per execution.
    ///
    /// Scoping: a fresh `ParallelWorkflowEngine` is built per execution (and per
    /// sub-workflow via `execute_subworkflow_graph`), so this `DashMap` never
    /// outlives a single run — there is no cross-execution leakage. Keyed on the
    /// resolved `module_id` (which the fetcher returns stably and which encodes
    /// the module's identity/version), so a node pointing at a different module
    /// version resolves to a different key and never reuses stale bytes.
    pub(crate) module_artifact_cache:
        Arc<dashmap::DashMap<Uuid, Arc<talos_workflow_engine_core::WasmModuleArtifact>>>,
    /// Pre-fetched sub-workflow graphs, keyed by `workflow_id`.
    /// Populated at execution start to avoid N+1 queries during node dispatch.
    /// Workflows referenced by `SubWorkflow`, `AgentLoop`, Ensemble, Judge,
    /// `ReflectiveRetry`, `LlmDispatch`, and `ReActLoop` nodes are batch-loaded
    /// in a single `WHERE id = ANY($1)` query. `DynamicDispatch` and
    /// `CapabilityDispatch` resolve workflow IDs at runtime and fall back to
    /// individual queries on cache miss.
    pub(crate) sub_workflow_cache: HashMap<Uuid, JsonValue>,
    /// When true, non-GET HTTP requests are mocked in the worker (returns 200 with `dry_run` metadata).
    /// Propagated to each `JobRequest` so the worker can intercept side effects.
    pub(crate) dry_run: bool,
    /// LLM data-egress tier ceiling. Controller stamps this from
    /// `actors.max_llm_tier` before running. Propagated to every
    /// `DispatchJob` and thus into every `JobRequest` the worker sees.
    /// Default `Tier1` (fail-closed) — see `set_max_llm_tier` for the
    /// canonical stamp path.
    pub(crate) max_llm_tier: talos_workflow_engine_core::LlmTier,
    /// Data-mutation ceiling stamped by `apply_actor_to_engine` from
    /// `actors.max_write_ceiling`. Propagated to every `DispatchJob` and
    /// thus into every `JobRequest`/`PipelineJobRequest` the worker sees.
    /// Permissive `Write` default (system/actor-less jobs); actor binding
    /// stamps the real ceiling (new actors → `ReadOnly`).
    pub(crate) max_write_ceiling: talos_workflow_engine_core::WriteCeiling,
    /// Blanket network-egress scope override, stamped by `apply_actor_to_engine`
    /// from `actors.egress_scope` (independent of `max_llm_tier`). `None` =
    /// tier-derived default. Propagated to every `DispatchJob`/`JobRequest`.
    pub(crate) egress_scope: Option<talos_workflow_engine_core::EgressScope>,
    /// Parent workflow definition id. Threaded into the
    /// [`NodeLifecycleHook::on_node_completed`] context so per-workflow
    /// cost rollups attribute to the right workflow row, not the
    /// per-run `execution_id`. Optional because some in-tree callers
    /// (tests, one-off diagnostic runs) don't have a durable workflow —
    /// dispatch sites fall back to `execution_id` when this is unset,
    /// which matches the pre-extraction behavior.
    pub(crate) workflow_id: Option<Uuid>,
    /// Pluggable evaluator for edge conditions, retry-delay expressions,
    /// and `Synthesize` expressions. In production wraps a `rhai::Engine`
    /// configured with sandbox limits; tests can plug in a no-op.
    pub(crate) expression_evaluator:
        Option<Arc<dyn talos_workflow_engine_core::ExpressionEvaluator>>,
    /// Pluggable output sanitizer — applied to node output / error
    /// strings before persistence. Production deployments typically
    /// wire a DLP-aware impl here; tests opt out via a passthrough.
    pub(crate) output_sanitizer: Option<Arc<dyn talos_workflow_engine_core::OutputSanitizer>>,
    /// Pluggable classifier for dispatch-error strings. Tells the
    /// retry loop whether a given failure is worth retrying. In
    /// production wraps `retry_intelligence`.
    pub(crate) retry_classifier: Option<Arc<dyn talos_workflow_engine_core::RetryClassifier>>,
    /// Pluggable per-dispatch audit log. Single-node + pipeline-step
    /// dispatch paths write a "running" row pre-dispatch and an
    /// "completed" / "failed" / "timeout" / "cancelled" row after the
    /// worker replies. In production writes to the `module_executions`
    /// Postgres table; tests plug in a capture impl.
    pub(crate) module_execution_store:
        Option<Arc<dyn talos_workflow_engine_core::ModuleExecutionStore>>,
    /// Pluggable human-in-the-loop approval gate. Nodes whose module
    /// declares `requires_approval_for: [...]` route through this
    /// before dispatch to check / create a pending approval row.
    /// In production writes to `execution_approvals`; tests can plug
    /// in an auto-approve or auto-deny impl.
    pub(crate) approval_gate: Option<Arc<dyn talos_workflow_engine_core::ApprovalGate>>,
    /// Read-side port for the ops-alerts triage store — powers the
    /// `ops_alerts_digest` system node (controller-side read; the
    /// store is deliberately not reachable from workers). `None`
    /// (out-of-tree consumers / tests without a store) makes the
    /// node emit an unavailable-envelope rather than failing the
    /// workflow.
    pub(crate) ops_alerts_reader: Option<Arc<dyn talos_workflow_engine_core::OpsAlertsReader>>,
    /// Read-side port for pending human approvals — powers the
    /// `pending_approvals` system node (controller-side read + one-click
    /// capability-URL mint; not reachable from workers). Same
    /// None-degrades contract as `ops_alerts_reader`.
    pub(crate) pending_approvals_reader:
        Option<Arc<dyn talos_workflow_engine_core::PendingApprovalsReader>>,
    /// Read-side port for the weekly assistant report — powers the
    /// `assistant_report` system node. Same None-degrades contract as
    /// `ops_alerts_reader`.
    pub(crate) assistant_report_reader:
        Option<Arc<dyn talos_workflow_engine_core::AssistantReportReader>>,
    /// Read-side port for the operator digest (autonomy cockpit) — powers
    /// the `operator_digest` system node. Same None-degrades contract as
    /// `assistant_report_reader`.
    pub(crate) operator_digest_reader:
        Option<Arc<dyn talos_workflow_engine_core::OperatorDigestReader>>,
    /// Write-side port for observe-only judge verdicts — the engine
    /// records each `Judge` / `InlineJudge` node's `(score, passed)` here
    /// (best-effort, spawned) so the weekly `assistant_report` node can
    /// aggregate them without reading the encrypted node outputs they
    /// live in. `None` (tests / out-of-tree consumers) skips recording.
    pub(crate) judge_score_recorder:
        Option<Arc<dyn talos_workflow_engine_core::JudgeScoreRecorder>>,
    /// Seals per-dispatch plaintext secrets into the opaque
    /// `(ciphertext, nonce)` pair forwarded on the wire. Defaults to
    /// [`talos_workflow_job_protocol::AesGcmSecretEnvelope`] — a
    /// production-grade AES-256-GCM impl with fresh nonces per
    /// dispatch. Override via
    /// [`set_secret_envelope`](Self::set_secret_envelope) only when
    /// the consumer's wire protocol sealed differently.
    ///
    /// The field is non-optional so the engine never silently
    /// downgrades to plaintext secret transport on the wire.
    pub(crate) secret_envelope: Arc<dyn talos_workflow_engine_core::SecretEnvelope>,
    /// Root directory under which per-execution scratch sandboxes are
    /// created. `Some(path)` → `<path>/<execution_id>` is created at
    /// run-start and torn down at run-end (RAII guard cleans up even on
    /// panic). `None` → sandbox creation is skipped entirely; modules
    /// that request filesystem scratch space will observe `None` and
    /// fall back to in-memory paths.
    ///
    /// Defaults to `Some(`[`default_sandbox_root()`](crate::default_sandbox_root)`)` —
    /// the platform-appropriate `<tmp>/workflow-engine-sandboxes`. Use
    /// [`set_sandbox_root`](Self::set_sandbox_root) to change or
    /// disable, e.g. when running on a read-only filesystem or a
    /// locked-down container.
    pub(crate) sandbox_root: Option<std::path::PathBuf>,
    /// Sliding-window cap on `__agent_history__` injection inside
    /// `AgentLoop` and `ReActLoop` bodies. Defaults to
    /// [`DEFAULT_AGENT_LOOP_MAX_HISTORY`]. Override per-engine via
    /// [`set_agent_loop_max_history`](Self::set_agent_loop_max_history).
    pub(crate) agent_loop_max_history: usize,
    /// Max successors prefetched per node when
    /// `speculative_prefetch: true` is set on the node config.
    /// Defaults to [`DEFAULT_MAX_PREFETCH_SUCCESSORS`].
    pub(crate) max_prefetch_successors: usize,
    /// Hard cap on `add_node` calls per engine instance. Defaults to
    /// [`DEFAULT_MAX_WORKFLOW_NODES`]; calls past the cap emit a
    /// warning and are dropped on the floor.
    pub(crate) max_workflow_nodes: usize,
    /// Per-node output size guard (bytes). Defaults to
    /// [`DEFAULT_MAX_NODE_OUTPUT_BYTES`]; outputs over the limit get
    /// replaced with an `__error: true` envelope so the result map /
    /// accumulated snapshot can't blow up downstream.
    pub(crate) max_node_output_bytes: usize,
    /// Upper bound on Wasmtime fuel granted to any single dispatch.
    /// Defaults to [`DEFAULT_MAX_FUEL_PER_NODE`]; caps both per-node
    /// `max_fuel` overrides from the graph JSON and the module's
    /// declared fuel budget.
    pub(crate) max_fuel_per_node: u64,
    /// Adaptive-fuel (Phase 2) learned ceilings, keyed by node LABEL (matching
    /// `execution_cost_rollup.node_id`). Populated by the controller via
    /// [`set_learned_fuel_ceilings`](Self::set_learned_fuel_ceilings) before a
    /// run; empty by default, in which case behaviour is identical to the
    /// static ceiling. Applied as a FLOOR in `resolve_node_max_fuel` — it can
    /// only ever RAISE a node's ceiling toward observed demand, never lower a
    /// deliberately-set value (so it can never introduce a new fuel failure).
    pub(crate) learned_fuel_ceilings: HashMap<String, u64>,
    /// Optional pluggable backing store for the per-module
    /// rate-limit counter. When `None` (the default), the engine
    /// uses the process-global in-memory `MODULE_RATE_LIMITS`
    /// `DashMap` — fine for single-process deployments. When `Some`,
    /// every `check_rate_limit` call routes through the trait
    /// instead, letting a sharded fleet share a counter (Redis,
    /// shared DB, etc.) so caps hold across replicas. See
    /// [`set_rate_limit_store`](Self::set_rate_limit_store).
    pub(crate) rate_limit_store: Option<Arc<dyn talos_workflow_engine_core::RateLimitStore>>,
    /// Optional engine-level cancellation token. When set, the
    /// non-`_cancellable` run methods (`run_with_transport`,
    /// `run_with_seed_with_transport`) consult this token before
    /// each dispatch and short-circuit with
    /// [`crate::WorkflowEngineError::Cancelled`] if it fires.
    /// Inherits through `AdapterSet` so sub-workflow loops see the
    /// same cancel signal as the parent.
    ///
    /// The `_cancellable` variants take a token as a parameter
    /// instead and ignore this field — useful when a single test
    /// run needs to control cancellation without persisting it on
    /// the engine. See
    /// [`set_cancellation_token`](Self::set_cancellation_token).
    pub(crate) cancellation_token: Option<tokio_util::sync::CancellationToken>,
    /// Recursion-depth ceiling for sub-workflow dispatch. Defaults
    /// to [`DEFAULT_MAX_SUBFLOW_DEPTH`]. Override via
    /// [`set_max_subflow_depth`](Self::set_max_subflow_depth).
    pub(crate) max_subflow_depth: usize,
    /// Current sub-workflow dispatch depth. `0` for the top-level
    /// engine; `N` for a sub-engine `N` levels deep. Set by
    /// [`AdapterSet::into_engine_with_graph`] when hydrating a
    /// sub-engine from the parent's adapter set.
    pub(crate) current_subflow_depth: usize,
}

impl Default for ParallelWorkflowEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Cloneable bundle of every policy-bearing adapter an engine holds.
///
/// Produced by [`ParallelWorkflowEngine::adapter_set`]; consumed by
/// [`AdapterSet::into_engine`] to produce a fresh engine with the
/// same adapters. Used by sub-workflow dispatch closures that need
/// to construct one or more child engines — the closure captures a
/// single `AdapterSet` clone and hydrates engines on demand.
///
/// Every field is an `Arc` (or `Copy`); `Clone` is a bounded number
/// of refcount bumps, not a deep copy. Cheap enough to clone
/// per-iteration inside an agent loop.
#[derive(Clone)]
pub struct AdapterSet {
    module_fetcher: Option<Arc<dyn ModuleFetcher>>,
    event_sink: Option<Arc<dyn EventSink>>,
    node_hook: Option<Arc<dyn NodeLifecycleHook>>,
    graph_store: Option<Arc<dyn WorkflowGraphStore>>,
    sub_actor_context_resolver:
        Option<Arc<dyn talos_workflow_engine_core::SubworkflowActorContextResolver>>,
    secrets_resolver: Option<Arc<dyn SecretsResolver>>,
    expression_evaluator: Option<Arc<dyn talos_workflow_engine_core::ExpressionEvaluator>>,
    output_sanitizer: Option<Arc<dyn talos_workflow_engine_core::OutputSanitizer>>,
    retry_classifier: Option<Arc<dyn talos_workflow_engine_core::RetryClassifier>>,
    module_execution_store: Option<Arc<dyn talos_workflow_engine_core::ModuleExecutionStore>>,
    approval_gate: Option<Arc<dyn talos_workflow_engine_core::ApprovalGate>>,
    ops_alerts_reader: Option<Arc<dyn talos_workflow_engine_core::OpsAlertsReader>>,
    pending_approvals_reader: Option<Arc<dyn talos_workflow_engine_core::PendingApprovalsReader>>,
    assistant_report_reader: Option<Arc<dyn talos_workflow_engine_core::AssistantReportReader>>,
    operator_digest_reader: Option<Arc<dyn talos_workflow_engine_core::OperatorDigestReader>>,
    judge_score_recorder: Option<Arc<dyn talos_workflow_engine_core::JudgeScoreRecorder>>,
    secret_envelope: Arc<dyn talos_workflow_engine_core::SecretEnvelope>,
    user_id: Option<Uuid>,
    actor_id: Option<Uuid>,
    dry_run: bool,
    /// LLM data-egress tier ceiling. Default `Tier1` (fail-closed);
    /// controller stamps in the actor's ceiling (`actors.max_llm_tier`)
    /// via `set_max_llm_tier` before running.
    max_llm_tier: talos_workflow_engine_core::LlmTier,
    max_write_ceiling: talos_workflow_engine_core::WriteCeiling,
    egress_scope: Option<talos_workflow_engine_core::EgressScope>,
    sandbox_root: Option<std::path::PathBuf>,
    agent_loop_max_history: usize,
    max_prefetch_successors: usize,
    max_workflow_nodes: usize,
    max_node_output_bytes: usize,
    max_fuel_per_node: u64,
    rate_limit_store: Option<Arc<dyn talos_workflow_engine_core::RateLimitStore>>,
    cancellation_token: Option<tokio_util::sync::CancellationToken>,
    max_subflow_depth: usize,
    current_subflow_depth: usize,
}

impl AdapterSet {
    /// Hydrate a fresh engine with this adapter set and populate its
    /// graph from `graph_json` — the common one-shot path for
    /// sub-workflow dispatch closures. Fails closed with a
    /// caller-provided error type via the inner
    /// [`load_from_graph_json`](ParallelWorkflowEngine::load_from_graph_json)
    /// error string.
    pub fn into_engine_with_graph(
        self,
        graph_json: &JsonValue,
    ) -> Result<ParallelWorkflowEngine, crate::WorkflowEngineError> {
        // Recursion-depth guard: every sub-workflow handler hydrates
        // through this method (Judge, Ensemble, AgentLoop, …). The
        // hydrated engine sits one dispatch level deeper than its
        // parent. Reject before doing any work if the chain would
        // exceed the configured ceiling — the alternative is a
        // stack overflow (or unbounded resource consumption) when a
        // workflow transitively references itself.
        let next_depth = self.current_subflow_depth.saturating_add(1);
        if next_depth > self.max_subflow_depth {
            return Err(crate::WorkflowEngineError::SubflowRecursionLimit {
                depth: next_depth,
                limit: self.max_subflow_depth,
            });
        }
        let mut engine = self.into_engine();
        engine.load_from_graph_json(graph_json)?;
        Ok(engine)
    }

    /// Hydrate a fresh engine with this adapter set. The returned
    /// engine has an empty graph; callers follow with
    /// [`ParallelWorkflowEngine::load_from_graph_json`] to populate.
    #[must_use]
    pub fn into_engine(self) -> ParallelWorkflowEngine {
        let mut engine = ParallelWorkflowEngine::new();
        engine.module_fetcher = self.module_fetcher;
        engine.event_sink = self.event_sink;
        engine.node_hook = self.node_hook;
        engine.graph_store = self.graph_store;
        engine.sub_actor_context_resolver = self.sub_actor_context_resolver;
        engine.secrets_resolver = self.secrets_resolver;
        engine.expression_evaluator = self.expression_evaluator;
        engine.output_sanitizer = self.output_sanitizer;
        engine.retry_classifier = self.retry_classifier;
        engine.module_execution_store = self.module_execution_store;
        engine.approval_gate = self.approval_gate;
        engine.ops_alerts_reader = self.ops_alerts_reader;
        engine.pending_approvals_reader = self.pending_approvals_reader;
        engine.assistant_report_reader = self.assistant_report_reader;
        engine.operator_digest_reader = self.operator_digest_reader;
        engine.judge_score_recorder = self.judge_score_recorder;
        engine.secret_envelope = self.secret_envelope;
        engine.user_id = self.user_id;
        engine.actor_id = self.actor_id;
        // The per-actor LLM-tier ceiling MUST travel with the sub-engine, in
        // lockstep with `actor_id`. Omitting it silently reset every
        // sub-workflow to `ParallelWorkflowEngine::new()`'s `Tier1` default
        // (fail-closed, but it strips external-LLM access from every judge /
        // ensemble / sub-workflow a tier-2 actor legitimately runs).
        engine.max_llm_tier = self.max_llm_tier;
        engine.max_write_ceiling = self.max_write_ceiling;
        engine.egress_scope = self.egress_scope;
        engine.dry_run = self.dry_run;
        engine.sandbox_root = self.sandbox_root;
        engine.agent_loop_max_history = self.agent_loop_max_history;
        engine.max_prefetch_successors = self.max_prefetch_successors;
        engine.max_workflow_nodes = self.max_workflow_nodes;
        engine.max_node_output_bytes = self.max_node_output_bytes;
        engine.max_fuel_per_node = self.max_fuel_per_node;
        engine.rate_limit_store = self.rate_limit_store;
        engine.cancellation_token = self.cancellation_token;
        engine.max_subflow_depth = self.max_subflow_depth;
        // The new engine is one level deeper than the parent. The
        // depth check happens in `into_engine_with_graph`; this
        // unguarded path is for tests / pre-load scenarios where
        // the caller is responsible for not creating cycles.
        engine.current_subflow_depth = self.current_subflow_depth.saturating_add(1);
        engine
    }
}

impl ParallelWorkflowEngine {
    /// Construct a bare engine with no adapters wired and the
    /// documented defaults for every limit / timeout / sandbox /
    /// agent-loop history setting.
    ///
    /// A fresh engine cannot dispatch on its own —
    /// [`run_with_transport`](Self::run_with_transport) refuses to
    /// proceed until [`set_secrets_resolver`](Self::set_secrets_resolver)
    /// has been called (and, for graphs containing module-backed
    /// nodes, [`set_module_fetcher`](Self::set_module_fetcher) and
    /// [`set_user_id`](Self::set_user_id)). The exact contract is
    /// enforced by [`precheck_runnable`] and surfaced through typed
    /// [`crate::WorkflowEngineError`] variants.
    ///
    /// For tests, prefer `talos_workflow_engine_test_utils::minimal_engine`
    /// which returns an engine with every adapter wired to an
    /// in-memory stub.
    ///
    /// [`precheck_runnable`]: Self::run_with_transport
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
            node_labels: HashMap::new(),
            learned_fuel_ceilings: HashMap::new(),
            node_configs: HashMap::new(),
            module_fetcher: None,
            event_sink: None,
            node_hook: None,
            checkpoint: None,
            graph_store: None,
            sub_actor_context_resolver: None,
            secrets_resolver: None,
            user_id: None,
            node_meta: HashMap::new(),
            execution_timeout_secs: 300,
            rate_limits: HashMap::new(),
            node_timeouts: HashMap::new(),
            actor_id: None,
            // SECURITY: default to Tier1 (local-only LLM egress).
            // `talos_engine::actor_binding::apply_actor_to_engine` overrides this
            // before `run()` / `run_with_seed()` so real dispatch is
            // unaffected. Tier1 is the fail-closed posture for any
            // code path that forgets the canonical actor-stamping step.
            // Paired with `DispatchJob::default()`'s Tier1 default so
            // the engine→dispatch chain is uniformly fail-closed.
            max_llm_tier: talos_workflow_engine_core::LlmTier::Tier1,
            egress_scope: None,
            // Permissive default; actor binding stamps `ReadOnly` for new
            // actors. Unlike Tier1 above, a `ReadOnly` default would break
            // trusted actor-less system writes (see DispatchJob::default).
            max_write_ceiling: talos_workflow_engine_core::WriteCeiling::Write,
            actor_context: None,
            module_prefetch_cache: Arc::new(dashmap::DashMap::new()),
            module_artifact_cache: Arc::new(dashmap::DashMap::new()),
            sub_workflow_cache: HashMap::new(),
            dry_run: false,
            workflow_id: None,
            expression_evaluator: None,
            output_sanitizer: None,
            retry_classifier: None,
            module_execution_store: None,
            approval_gate: None,
            ops_alerts_reader: None,
            pending_approvals_reader: None,
            assistant_report_reader: None,
            operator_digest_reader: None,
            judge_score_recorder: None,
            secret_envelope: Arc::new(talos_workflow_job_protocol::AesGcmSecretEnvelope),
            sandbox_root: Some(default_sandbox_root().to_path_buf()),
            agent_loop_max_history: DEFAULT_AGENT_LOOP_MAX_HISTORY,
            max_prefetch_successors: DEFAULT_MAX_PREFETCH_SUCCESSORS,
            max_workflow_nodes: DEFAULT_MAX_WORKFLOW_NODES,
            max_node_output_bytes: DEFAULT_MAX_NODE_OUTPUT_BYTES,
            max_fuel_per_node: DEFAULT_MAX_FUEL_PER_NODE,
            rate_limit_store: None,
            cancellation_token: None,
            max_subflow_depth: DEFAULT_MAX_SUBFLOW_DEPTH,
            current_subflow_depth: 0,
        }
    }

    /// Snapshot of this engine's policy adapters + user/actor context.
    /// Used by sub-workflow dispatch sites — clone the snapshot into an
    /// `async move` closure, then hydrate a fresh sub-engine inside the
    /// closure via [`AdapterSet::into_engine`].
    ///
    /// Every adapter is an `Arc`; cloning the set is a bounded number
    /// of refcount bumps (12 at most), not a deep copy. The set has no
    /// graph state — that's what
    /// [`load_from_graph_json`](Self::load_from_graph_json) is for.
    #[must_use]
    pub fn adapter_set(&self) -> AdapterSet {
        AdapterSet {
            module_fetcher: self.module_fetcher.clone(),
            event_sink: self.event_sink.clone(),
            node_hook: self.node_hook.clone(),
            graph_store: self.graph_store.clone(),
            sub_actor_context_resolver: self.sub_actor_context_resolver.clone(),
            secrets_resolver: self.secrets_resolver.clone(),
            expression_evaluator: self.expression_evaluator.clone(),
            output_sanitizer: self.output_sanitizer.clone(),
            retry_classifier: self.retry_classifier.clone(),
            module_execution_store: self.module_execution_store.clone(),
            approval_gate: self.approval_gate.clone(),
            ops_alerts_reader: self.ops_alerts_reader.clone(),
            pending_approvals_reader: self.pending_approvals_reader.clone(),
            assistant_report_reader: self.assistant_report_reader.clone(),
            operator_digest_reader: self.operator_digest_reader.clone(),
            judge_score_recorder: self.judge_score_recorder.clone(),
            secret_envelope: self.secret_envelope.clone(),
            user_id: self.user_id,
            actor_id: self.actor_id,
            dry_run: self.dry_run,
            max_llm_tier: self.max_llm_tier,
            max_write_ceiling: self.max_write_ceiling,
            egress_scope: self.egress_scope,
            sandbox_root: self.sandbox_root.clone(),
            agent_loop_max_history: self.agent_loop_max_history,
            max_prefetch_successors: self.max_prefetch_successors,
            max_workflow_nodes: self.max_workflow_nodes,
            max_node_output_bytes: self.max_node_output_bytes,
            max_fuel_per_node: self.max_fuel_per_node,
            rate_limit_store: self.rate_limit_store.clone(),
            cancellation_token: self.cancellation_token.clone(),
            max_subflow_depth: self.max_subflow_depth,
            // Carry the parent's depth — the sub-engine hydrated
            // from this AdapterSet sits one level deeper, computed
            // by `into_engine` / `into_engine_with_graph`.
            current_subflow_depth: self.current_subflow_depth,
        }
    }

    /// Build a fresh engine that reuses this engine's policy adapters
    /// and user/actor context — `self.adapter_set().into_engine()` in
    /// one call. Use this on `&self` paths; for async-move closures
    /// that need multiple sub-engines, capture an [`AdapterSet`] and
    /// re-hydrate each iteration instead.
    #[must_use]
    pub fn new_subengine(&self) -> Self {
        self.adapter_set().into_engine()
    }

    // ── Thin shims over the configured trait objects ──────────────────
    //
    // These exist so engine-body call sites read as `self.eval_bool(...)`
    // instead of `self.expression_evaluator.as_ref().map(|e| e.eval_bool(...)).unwrap_or(false)`.
    // Each shim falls back to a "safe default" when the trait is unset:
    // - `eval_bool` → `false` (condition not satisfied)
    // - `eval_bool_with_error` → `Err("no evaluator")` so callers surface the misconfiguration
    // - `eval_json` → `Err("no evaluator")` likewise
    // - `eval_i64` → `None`
    // - `redact_str` / `redact_json` → passthrough (no scrubbing)
    // - `classify_error` / `is_transient_error` → `"unknown"` / `false`
    // In production every constructor (`with_registry`, `with_services*`)
    // wires these via `wire_default_policy_adapters`, so the fallbacks
    // never fire on real traffic; they're only for bare `new()` test engines.

    pub(crate) fn eval_bool(&self, expression: &str, context: &JsonValue) -> bool {
        self.expression_evaluator
            .as_ref()
            .map(|e| e.eval_bool(expression, context))
            .unwrap_or(false)
    }

    fn try_eval_bool(&self, expression: &str, context: &JsonValue) -> Result<bool, String> {
        self.expression_evaluator
            .as_ref()
            .ok_or_else(|| "no ExpressionEvaluator configured".to_string())?
            .try_eval_bool(expression, context)
            .map_err(|e| e.to_string())
    }

    pub(crate) fn eval_json(
        &self,
        expression: &str,
        context: &JsonValue,
    ) -> Result<JsonValue, String> {
        self.expression_evaluator
            .as_ref()
            .ok_or_else(|| "no ExpressionEvaluator configured".to_string())?
            .eval_json(expression, context)
            .map_err(|e| e.to_string())
    }

    pub(crate) fn redact_str(&self, s: &str) -> String {
        self.output_sanitizer
            .as_ref()
            .map(|sz| sz.redact_str(s))
            .unwrap_or_else(|| s.to_string())
    }

    pub(crate) fn redact_json(&self, v: &JsonValue) -> JsonValue {
        self.output_sanitizer
            .as_ref()
            .map(|sz| sz.redact_json(v))
            .unwrap_or_else(|| v.clone())
    }

    /// Build a per-run [`ExecutionSanitizer`] from this engine's
    /// configured output sanitizer. Returns `None` when no sanitizer
    /// is wired (bare test engines); call sites substitute the
    /// stateless `redact_str` in that case.
    ///
    /// [`ExecutionSanitizer`]: talos_workflow_engine_core::ExecutionSanitizer
    fn new_execution_sanitizer(
        &self,
    ) -> Option<Box<dyn talos_workflow_engine_core::ExecutionSanitizer>> {
        let sanitizer = self.output_sanitizer.as_ref()?;
        let configs: Vec<JsonValue> = self.node_configs.values().cloned().collect();
        Some(sanitizer.new_execution(&configs))
    }

    /// Build encrypted secrets for a node dispatch.
    ///
    /// Thin wrapper around [`build_encrypted_secrets_for`] that sources
    /// `vault_paths` from the node's own config and has no additional
    /// declared paths. Prefer this form on call sites that hold `&self`.
    ///
    /// L-1 (2026-05-22): binds the dispatching `execution_id` as
    /// AEAD AAD on the AES-GCM tag. The worker decrypts with the
    /// same AAD (from `JobRequest.workflow_execution_id`) — a
    /// ciphertext transposed between executions under the same
    /// shared key fails decryption at the worker, providing an
    /// in-protocol integrity gate independent of the `JobRequest`
    /// HMAC. The caller passes `execution_id` because the engine
    /// itself doesn't hold one — it's a per-dispatch parameter.
    pub(crate) async fn build_encrypted_secrets(
        &self,
        node_id: Uuid,
        execution_id: Uuid,
        worker_shared_key: &Option<talos_workflow_engine_core::WorkerSharedKey>,
    ) -> talos_workflow_job_protocol::EncryptedSecrets {
        let (Some(resolver), Some(key)) = (self.secrets_resolver.as_ref(), worker_shared_key)
        else {
            return talos_workflow_job_protocol::EncryptedSecrets::empty();
        };
        let vault_paths = self
            .node_configs
            .get(&node_id)
            .map(|cfg| extract_vault_paths(cfg))
            .unwrap_or_default();
        build_encrypted_secrets_for(
            resolver.as_ref(),
            self.secret_envelope.as_ref(),
            node_id,
            self.user_id,
            &vault_paths,
            &[],
            key.as_bytes(),
            self.max_llm_tier,
            execution_id.as_bytes(),
        )
        .await
    }

    /// RFC 0010 P3 (D3b): `&self` sibling of [`build_encrypted_secrets`] that
    /// returns [`DispatchSecrets`] — inline WSK envelope OR the plaintext map for
    /// claim-based sealing, per `TALOS_ENVELOPE_SEALING`. Used by the loop-node
    /// path so loop bodies seal exactly like single-node dispatches (and thus
    /// don't fail the worker downgrade guard under `required`). Resolve once and
    /// clone per iteration (`DispatchSecrets: Clone`).
    pub(crate) async fn build_dispatch_secrets(
        &self,
        node_id: Uuid,
        execution_id: Uuid,
        worker_shared_key: &Option<talos_workflow_engine_core::WorkerSharedKey>,
    ) -> crate::secrets_pipeline::DispatchSecrets {
        let (Some(resolver), Some(key)) = (self.secrets_resolver.as_ref(), worker_shared_key)
        else {
            return crate::secrets_pipeline::DispatchSecrets::default();
        };
        let vault_paths = self
            .node_configs
            .get(&node_id)
            .map(|cfg| extract_vault_paths(cfg))
            .unwrap_or_default();
        crate::secrets_pipeline::build_dispatch_secrets_for(
            resolver.as_ref(),
            self.secret_envelope.as_ref(),
            node_id,
            self.user_id,
            &vault_paths,
            &[],
            key.as_bytes(),
            self.max_llm_tier,
            execution_id.as_bytes(),
        )
        .await
    }

    /// Execute the graph in parallel using a caller-supplied
    /// [`NodeDispatcher`] — the engine's primary public API and the
    /// **fresh-run** entry point.
    ///
    /// Use this for a workflow run that starts from scratch with no
    /// prior state. For a run that picks up from a checkpoint or an
    /// external-trigger payload, use
    /// [`run_with_seed_with_transport`](Self::run_with_seed_with_transport).
    ///
    /// Linear chains (maximal sequences of nodes with in-degree=1 / out-degree=1)
    /// are batched through `NodeDispatcher::dispatch_chain` in a
    /// single round-trip. Other nodes dispatch one-per-tokio-task with
    /// `FuturesUnordered`-bounded concurrency.
    ///
    /// Callers using `talos-workflow-engine-nats` build a
    /// `NatsNodeDispatcher`; other transports supply their own impl.
    /// See [`docs/custom-dispatcher.md`](https://github.com/aegix-dev/talos-workflow-engine/blob/main/docs/custom-dispatcher.md)
    /// for the integration walkthrough.
    ///
    /// # Errors
    ///
    /// * [`WorkflowEngineError::SecretsResolverMissing`] when no
    ///   [`SecretsResolver`] is configured. Fails closed before any
    ///   dispatch happens because every dispatch site requires one to
    ///   encrypt per-node secrets — an unset resolver would otherwise
    ///   produce empty-ciphertext dispatches (silent security
    ///   regression observed in a prior incident).
    /// * [`WorkflowEngineError::GraphCyclic`] when the loaded graph
    ///   has a cycle.
    /// * [`WorkflowEngineError::Timeout`] when the workflow exceeded
    ///   its configured wall-clock cap (see
    ///   [`set_execution_timeout`](Self::set_execution_timeout)).
    ///   Carries the configured `secs` so callers can produce
    ///   diagnostic messages without parsing.
    /// * [`WorkflowEngineError::Execution`] for other run-time
    ///   failures the engine has not yet promoted to a typed variant
    ///   (dispatch error, sub-workflow failure, etc.); the message
    ///   body is human-readable but **not** stable for
    ///   pattern-matching.
    ///
    /// [`NodeDispatcher`]: talos_workflow_engine_core::NodeDispatcher
    /// [`SecretsResolver`]: talos_workflow_engine_core::SecretsResolver
    /// [`WorkflowEngineError::SecretsResolverMissing`]: crate::WorkflowEngineError::SecretsResolverMissing
    /// [`WorkflowEngineError::GraphCyclic`]: crate::WorkflowEngineError::GraphCyclic
    /// [`WorkflowEngineError::Timeout`]: crate::WorkflowEngineError::Timeout
    /// [`WorkflowEngineError::Execution`]: crate::WorkflowEngineError::Execution
    pub async fn run_with_transport(
        &self,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
        execution_id: Uuid,
    ) -> Result<WorkflowContext, crate::WorkflowEngineError> {
        self.precheck_runnable()?;
        // Consult the engine-level cancellation token if one was
        // wired via `set_cancellation_token`. Callers needing a
        // one-off override use `run_with_transport_cancellable`
        // instead, which takes a token as a parameter and ignores
        // this field.
        run_with_workflow_timeout(
            self.execution_timeout_secs,
            self.cancellation_token.clone(),
            self.run_inner(dispatcher, worker_shared_key, HashMap::new(), execution_id),
        )
        .await
    }

    /// Cancellable variant of [`run_with_transport`](Self::run_with_transport).
    ///
    /// Identical semantics except the caller can short-circuit the
    /// reactor by cancelling `cancel`. The engine returns
    /// [`crate::WorkflowEngineError::Cancelled`] as soon as the token
    /// fires, bypassing whatever future the reactor was awaiting.
    ///
    /// # In-flight worker dispatches
    ///
    /// Cancellation only stops the engine's own scheduling. Workers
    /// already executing a `DispatchJob` continue until they
    /// complete on their own — the engine has no out-of-band channel
    /// to abort them. [`DispatchJob`](talos_workflow_engine_core::DispatchJob)
    /// carries no cancellation handle; if your transport supports
    /// mid-flight cancellation (e.g. NATS request-reply with a side
    /// subject), implement it inside your `NodeDispatcher` using the
    /// transport's own channel — there is no engine-level field to thread
    /// it through.
    ///
    /// Use [`tokio_util::sync::CancellationToken::new`] to construct
    /// a token; clone it as needed to share with the cancel-trigger
    /// site.
    pub async fn run_with_transport_cancellable(
        &self,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
        execution_id: Uuid,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<WorkflowContext, crate::WorkflowEngineError> {
        self.precheck_runnable()?;
        run_with_workflow_timeout(
            self.execution_timeout_secs,
            Some(cancel),
            self.run_inner(dispatcher, worker_shared_key, HashMap::new(), execution_id),
        )
        .await
    }

    /// Execute the graph with pre-seeded node results — the resume
    /// path complement to [`run_with_transport`](Self::run_with_transport).
    ///
    /// `initial_results` maps node UUIDs to their pre-computed output.
    /// Every node in this map is treated as **already completed**; the
    /// engine skips them and only schedules their successors (and
    /// their successors' successors). This is the engine's primary
    /// resume primitive:
    ///
    /// * **Resume from a checkpoint** — load a prior run's snapshot
    ///   from your [`CheckpointStore`] impl and pass it in. Use the
    ///   same `execution_id` so events / audit rows correlate.
    /// * **Webhook / external-trigger continuation** — when a `Wait`
    ///   or approval gate returns external input, seed the paused
    ///   node with the resolved value and resume.
    /// * **Re-running a single subtree** — seed every node *outside*
    ///   the subtree with its prior output to force the engine to
    ///   re-dispatch only what's downstream of your changes.
    ///
    /// The pipeline-chain optimisation is **disabled** on this path:
    /// the chain detector would otherwise build chains spanning
    /// already-completed seeded nodes and re-dispatch them. Per-node
    /// dispatch throughput is unchanged; large linear graphs may pay
    /// a few extra round-trips on resume.
    ///
    /// See [`docs/checkpoint-lifecycle.md`](https://github.com/aegix-dev/talos-workflow-engine/blob/main/docs/checkpoint-lifecycle.md)
    /// for the full pause-and-resume walkthrough.
    ///
    /// # Errors
    ///
    /// Same error contract as [`Self::run_with_transport`].
    ///
    /// [`CheckpointStore`]: talos_workflow_engine_core::CheckpointStore
    pub fn run_with_seed_with_transport(
        &self,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
        initial_results: HashMap<Uuid, JsonValue>,
        execution_id: Uuid,
    ) -> Pin<
        Box<dyn Future<Output = Result<WorkflowContext, crate::WorkflowEngineError>> + Send + '_>,
    > {
        // Abstract-entry guard mirrors `run_with_transport`.
        if let Err(e) = self.precheck_runnable() {
            return Box::pin(async move { Err(e) });
        }
        let timeout_secs = self.execution_timeout_secs;
        // Engine-level cancel propagation; see set_cancellation_token.
        let cancel = self.cancellation_token.clone();
        let inner = self.run_inner(dispatcher, worker_shared_key, initial_results, execution_id);
        Box::pin(async move { run_with_workflow_timeout(timeout_secs, cancel, inner).await })
    }

    /// Cancellable variant of
    /// [`run_with_seed_with_transport`](Self::run_with_seed_with_transport).
    /// See [`run_with_transport_cancellable`](Self::run_with_transport_cancellable)
    /// for the cancellation contract — same semantics on the seeded
    /// resume path.
    pub fn run_with_seed_with_transport_cancellable(
        &self,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
        initial_results: HashMap<Uuid, JsonValue>,
        execution_id: Uuid,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Pin<
        Box<dyn Future<Output = Result<WorkflowContext, crate::WorkflowEngineError>> + Send + '_>,
    > {
        if let Err(e) = self.precheck_runnable() {
            return Box::pin(async move { Err(e) });
        }
        let timeout_secs = self.execution_timeout_secs;
        let inner = self.run_inner(dispatcher, worker_shared_key, initial_results, execution_id);
        Box::pin(async move { run_with_workflow_timeout(timeout_secs, Some(cancel), inner).await })
    }

    /// Execute the graph with a caller-supplied **trigger input** —
    /// the fresh-run entry point for workflows that expect an external
    /// payload (webhook body, job arguments, upstream event, …) at
    /// their root.
    ///
    /// Equivalent to [`run_with_transport`](Self::run_with_transport)
    /// except the engine installs a synthetic root node that carries
    /// `trigger_input` as its output, then wires it to every current
    /// root so root-level modules execute with the trigger as their
    /// input. Callers that previously hand-rolled this pattern —
    /// adding a synthetic node, wiring it to roots, seeding
    /// `initial_results`, and dispatching — collapse the dance into a
    /// single call.
    ///
    /// The mechanism is internal. The synthetic node's identity, its
    /// label, and how it's wired are implementation details: a future
    /// release may seed root outputs natively without a fake parent
    /// node, and callers using this method will see no breakage.
    ///
    /// # Mutation and idempotence
    ///
    /// Takes `&mut self` because installing the trigger adds a node
    /// and edges to the engine's graph. Calling the method more than
    /// once on the same engine is safe: the second call reuses the
    /// synthetic trigger created by the first and only adds edges to
    /// new roots that have appeared in the graph since.
    ///
    /// # Errors
    ///
    /// Same error contract as
    /// [`run_with_transport`](Self::run_with_transport).
    pub async fn run_with_trigger_input_transport(
        &mut self,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
        trigger_input: JsonValue,
        execution_id: Uuid,
    ) -> Result<WorkflowContext, crate::WorkflowEngineError> {
        let trigger_node_id = self.ensure_trigger_node_wired_to_roots();
        let mut initial_results = HashMap::new();
        initial_results.insert(trigger_node_id, trigger_input);
        self.run_with_seed_with_transport(
            dispatcher,
            worker_shared_key,
            initial_results,
            execution_id,
        )
        .await
    }

    /// Cancellable variant of
    /// [`run_with_trigger_input_transport`](Self::run_with_trigger_input_transport).
    /// See [`run_with_transport_cancellable`](Self::run_with_transport_cancellable)
    /// for the cancellation contract — same semantics on the
    /// trigger-input path.
    pub async fn run_with_trigger_input_transport_cancellable(
        &mut self,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
        trigger_input: JsonValue,
        execution_id: Uuid,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<WorkflowContext, crate::WorkflowEngineError> {
        let trigger_node_id = self.ensure_trigger_node_wired_to_roots();
        let mut initial_results = HashMap::new();
        initial_results.insert(trigger_node_id, trigger_input);
        self.run_with_seed_with_transport_cancellable(
            dispatcher,
            worker_shared_key,
            initial_results,
            execution_id,
            cancel,
        )
        .await
    }

    /// Pre-dispatch sanity checks shared by [`run_with_transport`] and
    /// [`run_with_seed_with_transport`].
    ///
    /// Each check fails closed with a typed
    /// [`crate::WorkflowEngineError`] variant rather than letting the
    /// underlying configuration mistake surface as a per-node failure
    /// deep inside the reactor. Documented in order of evaluation:
    ///
    /// 1. [`SecretsResolverMissing`](crate::WorkflowEngineError::SecretsResolverMissing)
    ///    — every dispatch encrypts per-node secrets through the
    ///    resolver; without one the engine would silently produce
    ///    empty-ciphertext dispatches (a 2026-04 production
    ///    regression).
    /// 2. [`ModuleFetcherMissing`](crate::WorkflowEngineError::ModuleFetcherMissing)
    ///    — only checked when the loaded graph references at least
    ///    one module-backed node. Pure-system-node graphs are still
    ///    runnable without a fetcher.
    /// 3. [`UserContextRequired`](crate::WorkflowEngineError::UserContextRequired)
    ///    — same scoping as the fetcher check: required only when a
    ///    module-backed node exists, since module-artifact
    ///    resolution is per-user (cross-tenant isolation).
    /// 4. [`GraphCyclic`](crate::WorkflowEngineError::GraphCyclic)
    ///    — cycle detection runs last because it's the most
    ///    expensive check on a large graph and the cheaper config
    ///    checks should short-circuit first.
    ///
    /// [`run_with_transport`]: Self::run_with_transport
    /// [`run_with_seed_with_transport`]: Self::run_with_seed_with_transport
    fn precheck_runnable(&self) -> Result<(), crate::WorkflowEngineError> {
        if self.secrets_resolver.is_none() {
            return Err(crate::WorkflowEngineError::SecretsResolverMissing);
        }
        let has_module_node = self
            .node_meta
            .values()
            .any(|(module_id, _, _)| module_id.is_some());
        if has_module_node {
            if self.module_fetcher.is_none() {
                return Err(crate::WorkflowEngineError::ModuleFetcherMissing);
            }
            if self.user_id.is_none() {
                return Err(crate::WorkflowEngineError::UserContextRequired);
            }
        }
        if petgraph::algo::is_cyclic_directed(&self.graph) {
            return Err(crate::WorkflowEngineError::GraphCyclic);
        }
        Ok(())
    }

    /// Unified scheduler body shared by [`run_with_transport`] and
    /// [`run_with_seed_with_transport`].
    ///
    /// The two entry points previously had separate ~2,000-line
    /// scheduler bodies that drifted on observability (the seeded path
    /// tracked per-node wall time and emitted `node_started` events;
    /// the fresh path did neither) and on timeout behavior (the
    /// seeded path enforced the workflow-level
    /// `execution_timeout_secs`; the fresh path ignored it entirely).
    /// The unified body enforces the more careful set of behaviors
    /// uniformly:
    ///
    /// * **Workflow-level timeout.** When `execution_timeout_secs > 0`
    ///   the scheduler is wrapped in [`tokio::time::timeout`]. This
    ///   prevents a runaway workflow (pathological retry loop, stuck
    ///   `Wait` dispatch, etc.) from holding resources forever even
    ///   when per-node timeouts are configured. Set
    ///   `execution_timeout_secs = 0` to disable.
    /// * **Per-node wall-time tracking.** Always populated on the
    ///   returned [`WorkflowContext::node_timings`], regardless of
    ///   entry point. Previously only populated by the seeded path.
    /// * **`node_started` events.** Always emitted before a
    ///   single-node future is pushed to `executing`. Previously only
    ///   emitted by the seeded path.
    ///
    /// Pipeline chain detection still runs only when
    /// `initial_results.is_empty()` — seeded resumes would otherwise
    /// build chains spanning already-completed nodes and re-dispatch
    /// them.
    ///
    /// Kept on a `String` error type so the reactor loop can use `?`
    /// against the internal `Result<_, String>` paths without
    /// wholesale refactor; the public wrappers promote failures to
    /// [`crate::WorkflowEngineError`].
    ///
    /// # Tracing
    ///
    /// The method is instrumented with a `workflow` span carrying
    /// `execution_id`, `workflow_id` (when the engine has one), and a
    /// `seeded` flag distinguishing fresh runs from resumed ones.
    /// Every `tracing` event emitted inside the reactor — per-node
    /// dispatch, retry, failure, completion — inherits the span, so
    /// production log pipelines can correlate without having to
    /// string-match UUIDs across lines.
    ///
    /// [`run_with_transport`]: Self::run_with_transport
    /// [`run_with_seed_with_transport`]: Self::run_with_seed_with_transport
    #[allow(clippy::too_many_lines)]
    #[tracing::instrument(
        name = "workflow",
        skip_all,
        fields(
            execution_id = %execution_id,
            workflow_id = ?self.workflow_id,
            seeded = !initial_results.is_empty(),
        ),
    )]
    async fn run_inner(
        &self,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
        initial_results: HashMap<Uuid, JsonValue>,
        execution_id: Uuid,
    ) -> Result<WorkflowContext, String> {
        // Workflow-level timeout enforcement was hoisted into the
        // public wrappers (`run_with_transport` /
        // `run_with_seed_with_transport`) so the typed
        // `WorkflowEngineError::Timeout` variant can be constructed
        // with the configured cap directly. Per-node timeouts and
        // sub-workflow timeouts still live inside the reactor.
        self.run_scheduler_loop(dispatcher, worker_shared_key, initial_results, execution_id)
            .await
    }

    /// The actual reactor loop, lifted out of [`run_inner`] so the
    /// timeout wrap in that method can treat the entire scheduler as
    /// a single future.
    #[allow(clippy::too_many_lines)]
    async fn run_scheduler_loop(
        &self,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
        initial_results: HashMap<Uuid, JsonValue>,
        execution_id: Uuid,
    ) -> Result<WorkflowContext, String> {
        // Per-run DLP sanitizer — built once from resolved node
        // configs and used to scrub error messages before persistence.
        // Stateless regex-based scrubs (crate::dlp::redact_*) run in a
        // second pass on top via `self.redact_str` / `self.redact_json`.
        let exec_ctx = self.new_execution_sanitizer();

        // Create per-execution sandboxed directory. The RAII guard
        // removes the directory even on panic.
        let (execution_sandbox, _sandbox_guard) = match self.sandbox_root.as_deref() {
            Some(base) => match create_execution_sandbox(base, execution_id) {
                Ok((sandbox, sandbox_path)) => {
                    tracing::debug!("Created execution sandbox: {}", execution_id);
                    (
                        Some(sandbox),
                        Some(SandboxGuard {
                            execution_id,
                            sandbox_path,
                        }),
                    )
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to create execution sandbox: {}. File I/O will be unavailable.",
                        e
                    );
                    (None, None)
                }
            },
            None => (None, None),
        };

        // Cycle check.
        if petgraph::algo::is_cyclic_directed(&self.graph) {
            return Err("Workflow contains a cycle".into());
        }

        let is_fresh_run = initial_results.is_empty();

        // Pipeline chain detection runs ONLY on fresh runs. On seeded
        // resume the detector would build chains spanning
        // already-completed nodes and re-dispatch them.
        //
        // After detection, drop any chain that touches a system node:
        // pipeline dispatch tries to resolve a wasm artifact for every
        // step, and `Wait` / `FanIn` / `Collect` / etc. have none. A
        // chain spanning a `Wait` would also defeat the pause-on-Wait
        // contract because the chain dispatch is atomic — there's no
        // way to short-circuit mid-chain.
        let chains: Vec<Vec<NodeIndex>> = if is_fresh_run {
            detect_linear_chains(&self.graph)
                .into_iter()
                .filter(|chain| {
                    chain.iter().all(|&idx| {
                        let node_id = self.graph[idx];
                        // Only module-backed nodes belong in a pipeline.
                        // `node_meta` carries `(module_id, retry, kind)`;
                        // a system kind disqualifies the node.
                        self.node_meta
                            .get(&node_id)
                            .map(|(module_id, _, kind)| module_id.is_some() && kind.is_none())
                            .unwrap_or(false)
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        let mut node_to_chain: HashMap<NodeIndex, usize> = HashMap::new();
        let mut chain_heads: HashSet<NodeIndex> = HashSet::new();
        for (chain_idx, chain) in chains.iter().enumerate() {
            chain_heads.insert(chain[0]);
            for &n in chain {
                node_to_chain.insert(n, chain_idx);
            }
        }

        // In-degree counter.
        let mut pending: HashMap<NodeIndex, usize> = HashMap::new();
        for idx in self.graph.node_indices() {
            let deps = self
                .graph
                .neighbors_directed(idx, Direction::Incoming)
                .count();
            pending.insert(idx, deps);
        }

        // Seed results and pre-propagate pending counts for already-
        // completed (seeded) nodes. The fresh-run case sees an empty
        // `initial_results` and this whole block is a no-op.
        let mut results: HashMap<Uuid, JsonValue> = initial_results;
        let seeded: HashSet<Uuid> = results.keys().copied().collect();
        for &node_id in &seeded {
            if let Some(&node_idx) = self.node_map.get(&node_id) {
                pending.insert(node_idx, 0);
                for child in self.graph.neighbors_directed(node_idx, Direction::Outgoing) {
                    if let Some(cnt) = pending.get_mut(&child) {
                        if *cnt > 0 {
                            *cnt -= 1;
                        }
                    }
                }
            }
        }

        // Initial ready queue: zero-pending nodes that weren't seeded.
        // Edge-condition evaluation happens in the reactor loop AFTER
        // nodes produce output, not here at seed time (seeded nodes may
        // be synthetic triggers whose output doesn't contain the fields
        // conditions reference).
        let mut ready: VecDeque<NodeIndex> = VecDeque::new();
        for idx in self.graph.node_indices() {
            let node_id = self.graph[idx];
            if pending.get(&idx).copied().unwrap_or(1) == 0 && !seeded.contains(&node_id) {
                ready.push_back(idx);
            }
        }

        // Trait-object futures so we can push both pipeline-chain and
        // single-node futures (different concrete async block types).
        let mut executing: FuturesUnordered<ExecFuture<'_>> = FuturesUnordered::new();
        let mut node_timings: HashMap<String, u64> = HashMap::new();
        let mut node_start_times: HashMap<NodeIndex, std::time::Instant> = HashMap::new();

        // P1: monotonic version tag for the `results` map, used to memoize the
        // Arc-wrapped accumulated-context snapshot so it is rebuilt once per
        // node-processing step rather than once per node dispatch (was
        // O(N²·S)). `results` is mutated from several places — the
        // `commit_result!` macro inline below AND the `route_system_node_output`
        // / `handle_completed_future` helpers that take `&mut results` — so
        // rather than chase every insert site, the version is bumped once at the
        // top of the inner work loop. Each inner iteration processes exactly one
        // node and ends in `continue`/`break`, so a single bump per iteration
        // guarantees the snapshot read at a dispatch site always reflects every
        // mutation committed by prior iterations (over-invalidation only forces a
        // harmless rebuild — it can never serve stale data). The macro keeps the
        // commit sites self-documenting and is the natural seam if a future
        // change needs finer-grained invalidation.
        let mut results_version: u64 = 0;
        let mut accumulated_memo: Option<(u64, Option<Arc<JsonValue>>)> = None;
        macro_rules! commit_result {
            ($id:expr, $value:expr) => {{
                results.insert($id, $value);
            }};
        }

        // M5: ceiling on concurrent node-dispatch futures (see
        // MAX_CONCURRENT_NODE_DISPATCH). Resolved once per run.
        let max_concurrent_nodes = *MAX_CONCURRENT_NODE_DISPATCH;

        // Main reactor loop.
        while !ready.is_empty() || !executing.is_empty() {
            // M5: stop pulling new work from `ready` once the in-flight pool is
            // full; fall through to `executing.next().await` below to drain a
            // slot first. Deadlock-safe: we only stop early while `executing` is
            // non-empty (it's at the cap), so a completion is always pending to
            // await. Synchronous / inline-await node kinds that don't push to
            // the pool simply get processed on the next pass once a slot frees —
            // correctness and ordering are unchanged, only dispatch is throttled.
            while executing.len() < max_concurrent_nodes {
                let Some(node_idx) = ready.pop_front() else {
                    break;
                };
                // P1: invalidate the accumulated-context memo once per node
                // step. Prior iterations may have committed results via the
                // `commit_result!` macro OR via the `&mut results` completion
                // helpers; bumping here (before any snapshot read in this
                // iteration) makes the next `build_accumulated_context_memo`
                // observe all of them. See the counter's declaration for why a
                // single bump-per-iteration is sufficient and conservative.
                results_version += 1;
                // ── Pipeline dispatch (chain head, fresh runs only) ──────
                if let Some(&chain_idx) = node_to_chain.get(&node_idx) {
                    // Only dispatch when we're at the chain head; non-
                    // head chain nodes roll up under the head's
                    // completion, so skip them here.
                    if !chain_heads.contains(&node_idx) {
                        continue;
                    }
                    let chain = chains[chain_idx].clone();
                    let chain_input = self.gather_inputs(node_idx, &results);
                    let accumulated_snapshot = Self::build_accumulated_context_memo(
                        &self.node_labels,
                        &results,
                        results_version,
                        &mut accumulated_memo,
                    );
                    let fut = self.run_pipeline_chain_dispatch(
                        chain,
                        chain_input,
                        accumulated_snapshot,
                        execution_id,
                        dispatcher.clone(),
                        worker_shared_key.clone(),
                    );
                    executing.push(Box::pin(fut)
                        as Pin<
                            Box<dyn Future<Output = (NodeIndex, Result<JsonValue, String>)> + Send>,
                        >);
                    continue;
                }

                let node_id = self.graph[node_idx];

                // ── Skip condition check (applies to ALL node kinds) ─────────
                if let Some(output) =
                    self.check_skip_condition(node_idx, node_id, execution_id, &results)
                {
                    commit_result!(node_id, output);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                // ── FanIn aggregation (local computation, no dispatch) ───────
                if let Some(output) = self.try_dispatch_fan_in(node_idx, node_id, &results) {
                    commit_result!(node_id, output);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                // ── Collect dispatch (local computation) ─────────────────────
                if let Some(output) =
                    self.try_dispatch_collect(node_idx, node_id, execution_id, &results)
                {
                    commit_result!(node_id, output);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                // ── Ops-alerts digest (controller-side triage-store read) ────
                //
                // Async (one injected-reader DB round-trip), output flows
                // downstream — so it takes the `route_system_node_output`
                // path like Judge, not the bare `commit_result!` of the
                // pure-local nodes. No worker dispatch and no secrets:
                // the `encrypted_secrets` discipline does not apply here
                // by construction (nothing leaves the controller).
                if let Some(output) = self
                    .try_dispatch_ops_alerts_digest(node_id, execution_id)
                    .await
                {
                    let chains_ctx = if is_fresh_run {
                        Some((chains.as_slice(), &node_to_chain))
                    } else {
                        None
                    };
                    self.route_system_node_output(
                        node_idx,
                        output,
                        execution_id,
                        chains_ctx,
                        &exec_ctx,
                        &mut results,
                        &mut pending,
                        &mut ready,
                    )
                    .await?;
                    continue;
                }

                // ── Pending approvals (controller-side read + link mint) ─────
                // Same async + route-downstream + degrade-not-fail contract
                // as the ops-alerts digest above. No worker dispatch and no
                // secrets on the wire — the capability URLs are minted
                // controller-side and flow downstream as node output.
                if let Some(output) = self
                    .try_dispatch_pending_approvals(node_id, execution_id)
                    .await
                {
                    let chains_ctx = if is_fresh_run {
                        Some((chains.as_slice(), &node_to_chain))
                    } else {
                        None
                    };
                    self.route_system_node_output(
                        node_idx,
                        output,
                        execution_id,
                        chains_ctx,
                        &exec_ctx,
                        &mut results,
                        &mut pending,
                        &mut ready,
                    )
                    .await?;
                    continue;
                }

                // ── Assistant report (controller-side weekly snapshot) ───────
                // Same async + route-downstream + degrade-not-fail contract
                // as the ops-alerts digest above.
                if let Some(output) = self
                    .try_dispatch_assistant_report(node_id, execution_id)
                    .await
                {
                    let chains_ctx = if is_fresh_run {
                        Some((chains.as_slice(), &node_to_chain))
                    } else {
                        None
                    };
                    self.route_system_node_output(
                        node_idx,
                        output,
                        execution_id,
                        chains_ctx,
                        &exec_ctx,
                        &mut results,
                        &mut pending,
                        &mut ready,
                    )
                    .await?;
                    continue;
                }

                // ── Operator digest (controller-side autonomy cockpit) ───────
                // Same async + route-downstream + degrade-not-fail contract
                // as the assistant report above.
                if let Some(output) = self
                    .try_dispatch_operator_digest(node_id, execution_id)
                    .await
                {
                    let chains_ctx = if is_fresh_run {
                        Some((chains.as_slice(), &node_to_chain))
                    } else {
                        None
                    };
                    self.route_system_node_output(
                        node_idx,
                        output,
                        execution_id,
                        chains_ctx,
                        &exec_ctx,
                        &mut results,
                        &mut pending,
                        &mut ready,
                    )
                    .await?;
                    continue;
                }

                // ── Synthesize dispatch (collect + optional Rhai synthesis) ──
                if let Some(output) =
                    self.try_dispatch_synthesize(node_idx, node_id, execution_id, &results)
                {
                    commit_result!(node_id, output);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                // ── Verify dispatch (step-level output verification) ─────────
                //
                // `try_dispatch_verify` returns:
                //   None                  — not a Verify node, skip
                //   Some(Ok(value))       — pass OR on_failure="passthrough":
                //                           store and continue
                //   Some(Err(msg))        — on_failure="error" fired:
                //                           route through the normal
                //                           completion-failure path so the
                //                           workflow actually fails (matches
                //                           the tool's documented contract).
                if let Some(verify_outcome) =
                    self.try_dispatch_verify(node_idx, node_id, execution_id, &results)
                {
                    match verify_outcome {
                        Ok(output) => {
                            commit_result!(node_id, output);
                            self.unblock_successors(node_idx, &mut pending, &mut ready);
                        }
                        Err(error_msg) => {
                            let chains_ctx = if is_fresh_run {
                                Some((chains.as_slice(), &node_to_chain))
                            } else {
                                None
                            };
                            self.handle_completed_future(
                                node_idx,
                                Err(error_msg),
                                execution_id,
                                0, // no wall_time for synchronous system-node eval
                                chains_ctx,
                                &exec_ctx,
                                &mut results,
                                &mut pending,
                                &mut ready,
                            )
                            .await?;
                        }
                    }
                    continue;
                }

                // ── Wait dispatch (pause until external resume) ──────────────
                //
                // Always-on; not feature-gated. The handler returns a
                // pause signal carrying the `__waiting__` envelope.
                // Inserting it into `results` and returning early lets
                // the caller's `CheckpointStore` snapshot the partial
                // run; the resume path threads the external input
                // through `run_with_seed_with_transport(seed = {wait_id
                // → external_value})` so successors see the
                // substituted value via gather_inputs.
                if let Some(outcome) = self.try_dispatch_wait(node_id, execution_id) {
                    use crate::scheduler_handlers::WaitOutcome;
                    let WaitOutcome::Pause { waiting_output } = outcome;
                    commit_result!(node_id, waiting_output);
                    return Ok(WorkflowContext {
                        results,
                        waiting: true,
                        ..Default::default()
                    });
                }

                // ── InlineJudge dispatch (sync expression-driven verdict) ────
                #[cfg(feature = "llm-primitives")]
                if let Some(output) = self.try_dispatch_inline_judge(node_idx, node_id, &results) {
                    // Observe-only: record the verdict for the weekly
                    // self-report before the output is routed onward.
                    self.record_judge_score(node_id, execution_id, &output);
                    let chains_ctx = if is_fresh_run {
                        Some((chains.as_slice(), &node_to_chain))
                    } else {
                        None
                    };
                    self.route_system_node_output(
                        node_idx,
                        output,
                        execution_id,
                        chains_ctx,
                        &exec_ctx,
                        &mut results,
                        &mut pending,
                        &mut ready,
                    )
                    .await?;
                    continue;
                }

                // ── Judge dispatch (LLM-as-Judge evaluation) ─────────────────
                #[cfg(feature = "llm-primitives")]
                if let Some(output) = self
                    .try_dispatch_judge(
                        node_idx,
                        node_id,
                        &dispatcher,
                        &worker_shared_key,
                        &results,
                    )
                    .await
                {
                    // Observe-only: record the verdict for the weekly
                    // self-report before the output is routed onward.
                    self.record_judge_score(node_id, execution_id, &output);
                    let chains_ctx = if is_fresh_run {
                        Some((chains.as_slice(), &node_to_chain))
                    } else {
                        None
                    };
                    self.route_system_node_output(
                        node_idx,
                        output,
                        execution_id,
                        chains_ctx,
                        &exec_ctx,
                        &mut results,
                        &mut pending,
                        &mut ready,
                    )
                    .await?;
                    continue;
                }

                // ── Ensemble dispatch (self-consistency / ensemble voting) ────
                #[cfg(feature = "llm-primitives")]
                if let Some(output) = self
                    .try_dispatch_ensemble(
                        node_idx,
                        node_id,
                        &dispatcher,
                        &worker_shared_key,
                        &results,
                    )
                    .await
                {
                    let chains_ctx = if is_fresh_run {
                        Some((chains.as_slice(), &node_to_chain))
                    } else {
                        None
                    };
                    self.route_system_node_output(
                        node_idx,
                        output,
                        execution_id,
                        chains_ctx,
                        &exec_ctx,
                        &mut results,
                        &mut pending,
                        &mut ready,
                    )
                    .await?;
                    continue;
                }

                // ── ConfidenceGate dispatch ───────────────────────────────────
                #[cfg(feature = "llm-primitives")]
                if let Some(outcome) = self
                    .try_dispatch_confidence_gate(node_idx, node_id, execution_id, &results)
                    .await
                {
                    use crate::scheduler_handlers::ConfidenceGateOutcome;
                    match outcome {
                        ConfidenceGateOutcome::Proceed(output) => {
                            commit_result!(node_id, output);
                            self.unblock_successors(node_idx, &mut pending, &mut ready);
                            continue;
                        }
                        ConfidenceGateOutcome::Pause { waiting_output } => {
                            commit_result!(node_id, waiting_output);
                            return Ok(WorkflowContext {
                                results,
                                waiting: true,
                                ..Default::default()
                            });
                        }
                        ConfidenceGateOutcome::Halt(error_msg) => {
                            // Mirror the verify-node fix: route the
                            // error mode through the standard
                            // completion-failure path so the workflow
                            // actually fails (and continue_on_error /
                            // error edges still get to participate).
                            let chains_ctx = if is_fresh_run {
                                Some((chains.as_slice(), &node_to_chain))
                            } else {
                                None
                            };
                            self.handle_completed_future(
                                node_idx,
                                Err(error_msg),
                                execution_id,
                                0,
                                chains_ctx,
                                &exec_ctx,
                                &mut results,
                                &mut pending,
                                &mut ready,
                            )
                            .await?;
                            continue;
                        }
                    }
                }

                // ── ReflectiveRetry dispatch ──────────────────────────────────
                #[cfg(feature = "llm-primitives")]
                if let Some(output) = self
                    .try_dispatch_reflective_retry(
                        node_idx,
                        node_id,
                        &dispatcher,
                        &worker_shared_key,
                        &results,
                    )
                    .await
                {
                    let chains_ctx = if is_fresh_run {
                        Some((chains.as_slice(), &node_to_chain))
                    } else {
                        None
                    };
                    self.route_system_node_output(
                        node_idx,
                        output,
                        execution_id,
                        chains_ctx,
                        &exec_ctx,
                        &mut results,
                        &mut pending,
                        &mut ready,
                    )
                    .await?;
                    continue;
                }

                // ── LlmDispatch dispatch (LLM-based routing) ──────────────────
                #[cfg(feature = "llm-primitives")]
                if let Some(output) = self
                    .try_dispatch_llm_dispatch(
                        node_idx,
                        node_id,
                        &dispatcher,
                        &worker_shared_key,
                        &results,
                    )
                    .await
                {
                    let chains_ctx = if is_fresh_run {
                        Some((chains.as_slice(), &node_to_chain))
                    } else {
                        None
                    };
                    self.route_system_node_output(
                        node_idx,
                        output,
                        execution_id,
                        chains_ctx,
                        &exec_ctx,
                        &mut results,
                        &mut pending,
                        &mut ready,
                    )
                    .await?;
                    continue;
                }

                // ── AgentLoop dispatch (ReAct-style iterative sub-workflow) ──
                #[cfg(feature = "llm-primitives")]
                if let Some(output) = self
                    .try_dispatch_agent_loop(
                        node_idx,
                        node_id,
                        &dispatcher,
                        &worker_shared_key,
                        &results,
                    )
                    .await
                {
                    commit_result!(node_id, output);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                // ── WhileLoop dispatch (local computation) ──────────────────
                if let Some(output) = self.try_dispatch_while_loop(node_idx, node_id, &results) {
                    commit_result!(node_id, output);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                // ── RepeatLoop dispatch (local computation) ─────────────────
                if let Some(output) = self.try_dispatch_repeat_loop(node_idx, node_id, &results) {
                    commit_result!(node_id, output);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                // ── SubWorkflow dispatch (parallel fan-out) ──────────────────
                //
                // When multiple sub_workflow nodes are ready at the same
                // time (e.g. staff-meeting fans out 3 standup sub-workflows
                // from a single trigger), this drains all sub_workflow
                // entries from `ready` and dispatches them concurrently via
                // `futures::future::join_all`.
                //
                // Pre-fix the inline `.await` blocked the inner reactor
                // loop on each dispatch — 3 ready sub-workflows ran one
                // after another (~60s wall-clock) instead of in parallel
                // (~22s, gated by the slowest). Regular module nodes have
                // always been concurrent via the `executing` futures pool;
                // sub_workflows just lacked an analogous path because the
                // dispatch needs `&self` and integrating with the pool
                // requires lifetime gymnastics — `join_all` here keeps the
                // borrow simple while delivering the same parallelism for
                // the common fan-out case.
                //
                // try_dispatch_sub_workflow itself emits node_started /
                // node_completed events per dispatch on the parent's
                // execution_id, so the per-node trace shows each child
                // with its own duration_ms.
                if self.is_sub_workflow_node(node_id) {
                    let mut sub_wf_batch: Vec<(NodeIndex, Uuid)> = vec![(node_idx, node_id)];
                    let mut keep: VecDeque<NodeIndex> = VecDeque::with_capacity(ready.len());
                    while let Some(other_idx) = ready.pop_front() {
                        let other_id = self.graph[other_idx];
                        if self.is_sub_workflow_node(other_id) {
                            sub_wf_batch.push((other_idx, other_id));
                        } else {
                            keep.push_back(other_idx);
                        }
                    }
                    ready = keep;

                    // `.copied()` yields owned `(NodeIndex, Uuid)` (both Copy) so
                    // the dispatch closure's arg isn't a borrow of the batch —
                    // `buffered` needs a higher-ranked closure that a
                    // `&(NodeIndex, Uuid)` arg does not satisfy. `sub_wf_batch`
                    // stays intact for the order-preserving zip below.
                    let dispatch_futs = sub_wf_batch.iter().copied().map(|(idx, id)| {
                        self.try_dispatch_sub_workflow(
                            idx,
                            id,
                            execution_id,
                            &dispatcher,
                            &worker_shared_key,
                            &results,
                        )
                    });
                    // M5: bound the sub-workflow fan-out to the same in-flight
                    // ceiling as the module-node pool. `join_all` ran ALL ready
                    // sub-workflows at once (and each recursively fans out),
                    // which could multiply into worker-fleet / NATS saturation.
                    // `buffered` runs at most `max_concurrent_nodes` concurrently
                    // and — crucially — yields results in INPUT ORDER, so the
                    // `sub_wf_batch.zip(outputs)` mapping below stays correct
                    // (unlike `buffer_unordered`).
                    let outputs: Vec<Option<JsonValue>> = futures::stream::iter(dispatch_futs)
                        .buffered(max_concurrent_nodes)
                        .collect()
                        .await;

                    for ((idx, id), output) in sub_wf_batch.into_iter().zip(outputs) {
                        if let Some(out) = output {
                            commit_result!(id, out);
                            self.unblock_successors(idx, &mut pending, &mut ready);
                        }
                    }
                    continue;
                }

                // ── DynamicDispatch (Rhai expression → target sub-workflow) ──
                //
                // Matches the verify-node (b69aad5) and confidence_gate
                // (a7dd2b3) pattern: handler returns
                // `Option<Result<JsonValue, String>>`, Err routes through
                // `handle_completed_future` so `continue_on_error` +
                // error edges get a chance. Prior behaviour stored the
                // `{__error: true, error_message: ...}` envelope directly
                // and let the workflow return `completed` despite the
                // dispatch failing — misleading output with no path for
                // downstream recovery.
                if let Some(outcome) = self
                    .try_dispatch_dynamic_dispatch(
                        node_idx,
                        node_id,
                        &dispatcher,
                        &worker_shared_key,
                        &results,
                    )
                    .await
                {
                    match outcome {
                        Ok(output) => {
                            commit_result!(node_id, output);
                            self.unblock_successors(node_idx, &mut pending, &mut ready);
                        }
                        Err(error_msg) => {
                            let chains_ctx = if is_fresh_run {
                                Some((chains.as_slice(), &node_to_chain))
                            } else {
                                None
                            };
                            self.handle_completed_future(
                                node_idx,
                                Err(error_msg),
                                execution_id,
                                0,
                                chains_ctx,
                                &exec_ctx,
                                &mut results,
                                &mut pending,
                                &mut ready,
                            )
                            .await?;
                        }
                    }
                    continue;
                }

                // ── CapabilityDispatch (match workflow by capability tags) ──
                if let Some(output) = self
                    .try_dispatch_capability_dispatch(
                        node_idx,
                        node_id,
                        &dispatcher,
                        &worker_shared_key,
                        &results,
                    )
                    .await
                {
                    if output
                        .get("__error")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        let continue_on_error = self
                            .node_configs
                            .get(&node_id)
                            .and_then(|c| c.get("__continue_on_error"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if !continue_on_error {
                            let err_msg = output
                                .get("error_message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("capability dispatch failed")
                                .to_string();
                            tracing::error!(
                                %node_id,
                                error = %err_msg,
                                "Capability dispatch failed — failing workflow"
                            );
                            return Err(format!("Capability dispatch node {node_id}: {err_msg}"));
                        }
                        tracing::info!(
                            %node_id,
                            "Capability dispatch failed but continue_on_error is set — continuing"
                        );
                    }
                    commit_result!(node_id, output);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                // ── Loop dispatch (re-dispatches body node) ──────────────────
                if let Some(output) = self
                    .try_dispatch_loop(
                        node_idx,
                        node_id,
                        execution_id,
                        &dispatcher,
                        &worker_shared_key,
                        &results,
                    )
                    .await
                {
                    // `run_loop_iterations` lifts `__error`/`error_message`
                    // to the top level when the loop terminated from a
                    // body failure (vs. condition-false / max-iterations).
                    // Honor `continue_on_error` the same way the
                    // capability-dispatch branch does.
                    if output
                        .get("__error")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        let continue_on_error = self
                            .node_configs
                            .get(&node_id)
                            .and_then(|c| c.get("__continue_on_error"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if !continue_on_error {
                            let err_msg = output
                                .get("error_message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("loop body failed")
                                .to_string();
                            let reason = output
                                .get("termination_reason")
                                .and_then(|v| v.as_str())
                                .unwrap_or("body_error");
                            tracing::error!(
                                %node_id,
                                termination_reason = %reason,
                                error = %err_msg,
                                "Loop terminated by body failure — failing workflow"
                            );
                            return Err(format!("Loop node {node_id}: {err_msg}"));
                        }
                        tracing::info!(
                            %node_id,
                            "Loop body failed but continue_on_error is set — continuing"
                        );
                    }
                    commit_result!(node_id, output);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                // ── ErrorHandler dispatch (pattern filtering) ───────────────
                if let Some(output) = self.try_dispatch_error_handler(node_idx, node_id, &results) {
                    commit_result!(node_id, output);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                // ── Single-node dispatch ─────────────────────────────────────
                if let Some(error_envelope) = self.check_rate_limit(node_id).await {
                    commit_result!(node_id, error_envelope);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                let inputs = self.gather_inputs(node_idx, &results);
                let accumulated_snapshot = Self::build_accumulated_context_memo(
                    &self.node_labels,
                    &results,
                    results_version,
                    &mut accumulated_memo,
                );
                // `__trigger_input__` is synthesized once from the
                // synthetic `__trigger__` node output (or unwrapped when
                // the parent was itself a sub-workflow — see
                // `extract_trigger_input`) and threaded into every
                // node's envelope so the scaffold's "always preserved"
                // contract is honored end to end.
                let trigger_input_val = self.extract_trigger_input(&results);
                let fut = self.run_single_node_dispatch(
                    node_idx,
                    node_id,
                    execution_id,
                    dispatcher.clone(),
                    worker_shared_key.clone(),
                    inputs,
                    accumulated_snapshot,
                    trigger_input_val,
                    execution_sandbox.clone(),
                );
                // Per-node timing + node_started event: always emitted
                // so callers using WorkflowContext.node_timings get
                // data regardless of entry point.
                node_start_times.insert(node_idx, std::time::Instant::now());
                emit_event_spawn(
                    &self.event_sink,
                    NodeEventWrite {
                        execution_id,
                        event_type: "node_started".to_string(),
                        node_id: Some(node_id),
                        status: "Running".to_string(),
                        log_message: None,
                        iteration_index: None,
                        error_class: None,
                    },
                );
                executing.push(Box::pin(fut)
                    as Pin<
                        Box<dyn Future<Output = (NodeIndex, Result<JsonValue, String>)> + Send>,
                    >);
                self.maybe_speculative_prefetch(node_id, node_idx);
                continue;
            }

            // Await next finished task and route its outcome through
            // the shared post-completion handler. Chain context is
            // passed only when chain detection actually ran
            // (fresh-run path); seeded runs supply `None`.
            if let Some((finished_idx, exec_result)) = executing.next().await {
                let wall_time_ms = if let Some(start) = node_start_times.remove(&finished_idx) {
                    let elapsed_ms = start.elapsed().as_millis() as u64;
                    let label = self
                        .node_labels
                        .get(&self.graph[finished_idx])
                        .cloned()
                        .unwrap_or_else(|| self.graph[finished_idx].to_string());
                    node_timings.insert(label, elapsed_ms);
                    elapsed_ms
                } else {
                    0
                };
                let chains_ctx = if is_fresh_run {
                    Some((chains.as_slice(), &node_to_chain))
                } else {
                    None
                };
                self.handle_completed_future(
                    finished_idx,
                    exec_result,
                    execution_id,
                    wall_time_ms,
                    chains_ctx,
                    &exec_ctx,
                    &mut results,
                    &mut pending,
                    &mut ready,
                )
                .await?;
            }
        }

        // Two-pass scrub: value-based then regex DLP patterns.
        let results: HashMap<Uuid, JsonValue> = results
            .into_iter()
            .map(|(k, v)| {
                let v = exec_ctx.as_ref().map(|c| c.redact_output(&v)).unwrap_or(v);
                (k, self.redact_json(&v))
            })
            .collect();

        // Release unconsumed prefetch cache entries.
        self.module_prefetch_cache.clear();
        // P2: release the per-execution module-artifact cache (multi-MB wasm
        // blobs). Per-execution scoping already prevents cross-run reuse, but
        // an engine handle that outlives its run (e.g. a resumed/seeded
        // scheduler reused by the caller) shouldn't pin the blobs.
        self.module_artifact_cache.clear();

        Ok(WorkflowContext {
            results,
            node_timings,
            ..Default::default()
        })
    }
}

// ============================================================================
// Tests — extracted to engine_tests.rs to keep this file focused on
// the impl. Mounted via #[path] so the test module is logically a
// child of engine and use super::* resolves to engine items.
// ============================================================================

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
