#![allow(dead_code)]

use futures::stream::{FuturesUnordered, StreamExt};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use serde_json::{Map, Value as JsonValue};
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
/// 60s covers both simple HTTP fetches (sub-second typical) and LLM synthesis
/// against Ollama (20-45s typical) without requiring every agent-node module
/// author to set a custom timeout. Individual nodes can still raise or lower
/// via `add_node_to_workflow(timeout_secs:…)`; there is no implicit clamp.
///
/// Respects `WASM_EXECUTION_TIMEOUT_SECS` env var for operator override —
/// matches `get_wasm_config`'s default so the tool output and actual
/// runtime behavior agree. Previously these defaults were hardcoded `30` at
/// five call sites and diverged from the configurable env default.
pub static DEFAULT_NODE_TIMEOUT_SECS: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("WASM_EXECUTION_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60)
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
    EdgeLogic, EventSink, JoinMode, ModuleFetcher, NodeEventWrite, NodeLifecycleHook,
    SecretsResolver, SystemNodeKind, WorkflowContext, WorkflowGraphStore,
};

// Checkpoint encryption + persistence is the responsibility of the
// consumer's `CheckpointStore` impl (see
// `talos_workflow_engine_core::CheckpointStore`). The engine itself
// holds only an `Arc<dyn CheckpointStore>` and never talks to a
// database directly.

use crate::graph_parser::{parse_system_node_kind, read_node_retry_policy_with_actor_cap};
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

/// Structured errors from [`ParallelWorkflowEngine::execute_subworkflow_graph`].
/// Callers convert these into their own error envelopes via
/// [`SubflowError::into_error_envelope`] so each system-node kind can keep its
/// own context-specific messages ("Judge workflow X not found", etc).
///
/// Marked [`#[non_exhaustive]`] so the engine can promote new failure modes
/// (invalid ownership, schema-version mismatch, ...) into their own variants
/// without breaking downstream `match` arms. Consumers should always include
/// a wildcard arm.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SubflowError {
    /// Engine has no registry configured — sub-workflow execution impossible.
    NoRegistry,
    /// Engine has no `user_id` — all sub-workflow execution requires it.
    NoUserId,
    /// Secrets resolver not attached — sub-workflow modules couldn't fetch secrets.
    NoSecretsResolver,
    /// No workflow matching `sub_wf_id` exists (or not visible to `user_id`).
    ///
    /// Typically means the referenced workflow was deleted after the
    /// parent graph was authored, or the parent and sub-workflow are
    /// owned by different users. Carries the missing ID so callers can
    /// surface a precise diagnostic (e.g. "judge workflow X was
    /// deleted; edit the parent to reference a valid judge").
    GraphNotFound(Uuid),
    /// `build_engine_from_graph_json_with_resolver` failed — usually a module resolution issue.
    BuildFailed(String),
    /// `run_with_seed` returned an error — execution actually ran and failed.
    ExecutionFailed(String),
}

impl SubflowError {
    /// Canonical `{__error, error_message}` envelope with a caller-provided
    /// context label (e.g. "Judge", "Ensemble child", "Sub-workflow").
    pub fn into_error_envelope(self, context: &str) -> JsonValue {
        let msg = match self {
            SubflowError::NoRegistry => {
                format!("Registry not available for {} node", context)
            }
            SubflowError::NoUserId => "user_id required for sub-workflow execution".to_string(),
            SubflowError::NoSecretsResolver => {
                format!("secrets resolver unavailable for {} execution", context)
            }
            SubflowError::GraphNotFound(id) => {
                format!("{} workflow {} not found", context, id)
            }
            SubflowError::BuildFailed(e) => {
                format!("Failed to build {} workflow engine: {}", context, e)
            }
            SubflowError::ExecutionFailed(e) => {
                format!("{} workflow execution failed: {}", context, e)
            }
        };
        serde_json::json!({ "__error": true, "error_message": msg })
    }

    /// Returns the missing sub-workflow id when this error is
    /// [`GraphNotFound`](Self::GraphNotFound), else `None`.
    ///
    /// Callers that need to branch on "missing sub-workflow" without
    /// exhaustively matching every variant (e.g. to surface a
    /// structured `{kind: "sub_workflow_not_found", id}` response in
    /// their API layer) can pattern-match on this accessor instead.
    pub fn missing_sub_workflow_id(&self) -> Option<Uuid> {
        match self {
            SubflowError::GraphNotFound(id) => Some(*id),
            _ => None,
        }
    }
}

/// Structured judge verdict parsed from a collapsed sub-workflow output.
///
/// Downstream consumers (`judge_node`, ensemble `best_of_n`) want the same 4 fields;
/// this struct centralizes parsing and logs when fields are missing so malformed
/// judge workflows fail loudly rather than silently scoring 0.0.
///
/// # Using outside the engine's own dispatch paths
///
/// Third-party call sites (HTTP handlers, CLI tools, contract tests) that
/// need to score a sub-workflow's output should construct one of these via
/// [`from_collapsed`](Self::from_collapsed) rather than hand-parsing the
/// JSON — otherwise the parse logic drifts from what the engine itself
/// uses to score judge nodes, and malformed-verdict warnings stop firing.
///
/// ```no_run
/// use serde_json::json;
/// use talos_workflow_engine::JudgeVerdict;
///
/// let collapsed = json!({
///     "score": 0.82,
///     "passed": true,
///     "reasoning": "meets the rubric",
///     "feedback": "tighten the closing line",
/// });
/// let verdict = JudgeVerdict::from_collapsed(&collapsed);
/// assert!(verdict.passed);
/// assert_eq!(verdict.malformed_field_count, 0);
/// ```
///
/// `Serialize` / `Deserialize` are implemented so the verdict can be
/// shipped over an API without an intermediate conversion.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JudgeVerdict {
    /// Verdict score in `0.0..=1.0`. Higher = better. Sub-workflow
    /// outputs missing this field default to `0.0`.
    pub score: f64,
    /// Did the upstream output pass the rubric? Sub-workflow outputs
    /// missing this field default to `false`.
    pub passed: bool,
    /// Human-readable explanation of the verdict. Used for audit
    /// trails and downstream context.
    pub reasoning: String,
    /// Suggested correction or improvement that downstream nodes
    /// (e.g. `ReflectiveRetry`) can feed back into the next attempt.
    pub feedback: String,
    /// Number of expected fields that were missing or wrong-typed in the
    /// sub-workflow output (0..=4). Non-zero indicates a malformed judge workflow.
    pub malformed_field_count: u8,
}

impl JudgeVerdict {
    /// Parse a verdict from a collapsed sub-workflow output. Missing/mistyped
    /// fields fall back to defaults and increment `malformed_field_count` so
    /// callers can surface the issue. Always returns a value — judge extraction
    /// must never panic at runtime.
    pub fn from_collapsed(verdict: &JsonValue) -> Self {
        let mut malformed = 0u8;
        let score = match verdict.get("score").and_then(|v| v.as_f64()) {
            Some(v) => v,
            None => {
                malformed += 1;
                0.0
            }
        };
        let passed = match verdict.get("passed").and_then(|v| v.as_bool()) {
            Some(v) => v,
            None => {
                malformed += 1;
                false
            }
        };
        let reasoning = match verdict.get("reasoning").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => {
                malformed += 1;
                String::new()
            }
        };
        let feedback = match verdict.get("feedback").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => {
                malformed += 1;
                String::new()
            }
        };
        if malformed > 0 {
            tracing::warn!(
                malformed_fields = malformed,
                "Judge sub-workflow returned malformed verdict — missing or wrong-typed fields. \
                 Expected {{score: f64, passed: bool, reasoning: string, feedback: string}}."
            );
        }
        Self {
            score,
            passed,
            reasoning,
            feedback,
            malformed_field_count: malformed,
        }
    }
}

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
    secret_envelope: Arc<dyn talos_workflow_engine_core::SecretEnvelope>,
    user_id: Option<Uuid>,
    actor_id: Option<Uuid>,
    dry_run: bool,
    /// LLM data-egress tier ceiling. Default `Tier1` (fail-closed);
    /// controller stamps in the actor's ceiling (`actors.max_llm_tier`)
    /// via `set_max_llm_tier` before running.
    max_llm_tier: talos_workflow_engine_core::LlmTier,
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
        engine.secret_envelope = self.secret_envelope;
        engine.user_id = self.user_id;
        engine.actor_id = self.actor_id;
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
            node_configs: HashMap::new(),
            module_fetcher: None,
            event_sink: None,
            node_hook: None,
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
            // `ActorRepository::apply_actor_to_engine` overrides this
            // before `run()` / `run_with_seed()` so real dispatch is
            // unaffected. Tier1 is the fail-closed posture for any
            // code path that forgets the canonical actor-stamping step.
            // Paired with `DispatchJob::default()`'s Tier1 default so
            // the engine→dispatch chain is uniformly fail-closed.
            max_llm_tier: talos_workflow_engine_core::LlmTier::Tier1,
            actor_context: None,
            module_prefetch_cache: Arc::new(dashmap::DashMap::new()),
            sub_workflow_cache: HashMap::new(),
            dry_run: false,
            workflow_id: None,
            expression_evaluator: None,
            output_sanitizer: None,
            retry_classifier: None,
            module_execution_store: None,
            approval_gate: None,
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

    // ──────────────────────────────────────────────────────────────
    // Accessors for internal engine state.
    //
    // These are the canonical public API for reading engine state.
    // The underlying struct fields are `pub(crate)` — not part of the
    // public API surface. Write access (where appropriate) uses the
    // dedicated setters on this impl block.
    // ──────────────────────────────────────────────────────────────

    /// The directed graph of nodes connected by [`EdgeLogic`] edges.
    #[must_use]
    pub fn graph(&self) -> &DiGraph<Uuid, EdgeLogic> {
        &self.graph
    }

    /// Mapping from node UUID → `NodeIndex` in the petgraph
    /// representation. Used by callers that need to traverse the
    /// topology (e.g. custom validators or graph visualizations).
    #[must_use]
    pub fn node_map(&self) -> &HashMap<Uuid, NodeIndex> {
        &self.node_map
    }

    /// Mapping from internal node UUID → user-facing node label
    /// (`"fetch"`, `"n1"`, etc.). Populated by
    /// [`load_graph_from_json`](Self::load_graph_from_json).
    #[must_use]
    pub fn node_labels(&self) -> &HashMap<Uuid, String> {
        &self.node_labels
    }

    /// Per-node configuration extracted from the graph JSON. Includes
    /// both user-supplied fields and engine-reserved keys (for example,
    /// `__skip_condition` / `__continue_on_error`).
    #[must_use]
    pub fn node_configs(&self) -> &HashMap<Uuid, serde_json::Value> {
        &self.node_configs
    }

    /// Per-node metadata: `(module_id, retry_policy, system_kind)`.
    /// `module_id` is `None` for system-only nodes; `system_kind` is
    /// `None` for plain module nodes.
    #[must_use]
    pub fn node_meta(
        &self,
    ) -> &HashMap<
        Uuid,
        (
            Option<Uuid>,
            Option<talos_workflow_engine_core::RetryPolicy>,
            Option<SystemNodeKind>,
        ),
    > {
        &self.node_meta
    }

    /// Workflow-level execution timeout in seconds. Default `300`
    /// (five minutes); overridden by the graph-root
    /// `execution_timeout_secs` field when a graph is loaded.
    ///
    /// When `> 0` the scheduler wraps the reactor in
    /// [`tokio::time::timeout`] — a runaway workflow (pathological
    /// retry loop, stuck `Wait` dispatch, etc.) can't hold resources
    /// past this cap. `0` is a sentinel meaning "no wall-clock cap;
    /// per-node timeouts are the only safety net" — see
    /// [`execution_timeout`](Self::execution_timeout) for the typed
    /// equivalent.
    #[must_use]
    pub fn execution_timeout_secs(&self) -> u64 {
        self.execution_timeout_secs
    }

    /// Workflow-level execution timeout as an `Option<Duration>` —
    /// the typed view of [`execution_timeout_secs`](Self::execution_timeout_secs).
    ///
    /// Returns `None` when the wall-clock cap is disabled, `Some(d)`
    /// otherwise. Sub-second precision is not preserved (the engine
    /// stores a `u64` of seconds internally).
    #[must_use]
    pub fn execution_timeout(&self) -> Option<std::time::Duration> {
        match self.execution_timeout_secs {
            0 => None,
            secs => Some(std::time::Duration::from_secs(secs)),
        }
    }

    /// Set the workflow-level execution timeout from a `u64` of seconds.
    ///
    /// Passing `0` **disables** the wall-clock cap; per-node timeouts
    /// become the only safety net. Prefer
    /// [`set_execution_timeout`](Self::set_execution_timeout)
    /// (`Option<Duration>`) on new code — the typed form makes
    /// "disabled" obvious at the call site instead of relying on a
    /// magic-zero sentinel. This shorter form remains for callers who
    /// already have a `u64` of seconds handy (graph JSON parsing,
    /// configuration files, environment variables).
    pub fn set_execution_timeout_secs(&mut self, secs: u64) {
        self.execution_timeout_secs = secs;
    }

    /// Set the workflow-level execution timeout from an `Option<Duration>`.
    ///
    /// `None` disables the wall-clock cap; `Some(d)` truncates to the
    /// nearest whole second and uses that as the cap. Equivalent to
    /// [`set_execution_timeout_secs`](Self::set_execution_timeout_secs)
    /// with `0` for the disabled case, but reads cleaner at call sites:
    ///
    /// ```ignore
    /// engine.set_execution_timeout(None);                                   // disabled
    /// engine.set_execution_timeout(Some(Duration::from_secs(60)));          // 60s
    /// ```
    pub fn set_execution_timeout(&mut self, timeout: Option<std::time::Duration>) {
        self.execution_timeout_secs = timeout.map_or(0, |d| d.as_secs());
    }

    /// Whether side-effectful dispatches are mocked out. See
    /// [`set_dry_run`](Self::set_dry_run).
    #[must_use]
    pub fn dry_run(&self) -> bool {
        self.dry_run
    }

    /// Replace the secret-sealing envelope. Accepts any
    /// [`SecretEnvelope`] impl. Defaults to AES-256-GCM; override
    /// only when the consumer's worker fleet speaks a different
    /// wire protocol (e.g. an HMAC-only shape, a post-quantum AEAD,
    /// or a pass-through envelope for tests).
    ///
    /// [`SecretEnvelope`]: talos_workflow_engine_core::SecretEnvelope
    pub fn set_secret_envelope(
        &mut self,
        envelope: Arc<dyn talos_workflow_engine_core::SecretEnvelope>,
    ) {
        self.secret_envelope = envelope;
    }

    /// Sliding-window cap on `__agent_history__` injection inside
    /// `AgentLoop` and `ReActLoop` bodies. See
    /// [`set_agent_loop_max_history`](Self::set_agent_loop_max_history)
    /// for the contract.
    #[must_use]
    pub fn agent_loop_max_history(&self) -> usize {
        self.agent_loop_max_history
    }

    /// Override the per-engine sliding-window cap on
    /// `__agent_history__` entries injected into `AgentLoop` /
    /// `ReActLoop` body iterations.
    ///
    /// The window holds the last N iteration outputs and rolls
    /// FIFO-style as new iterations land. Defaults to
    /// [`DEFAULT_AGENT_LOOP_MAX_HISTORY`] (20). Larger values let an
    /// agent reason over more history at the cost of context size on
    /// every iteration; smaller values trim context but lose long-
    /// range reasoning.
    ///
    /// `0` is accepted and disables history injection entirely
    /// (equivalent to `inject_history: false` on every loop variant
    /// in the graph). Useful for stateless / pure-tool agents.
    pub fn set_agent_loop_max_history(&mut self, max_history: usize) {
        self.agent_loop_max_history = max_history;
    }

    /// Maximum number of successor nodes the engine prefetches per
    /// node when `speculative_prefetch: true` is set. See
    /// [`set_max_prefetch_successors`](Self::set_max_prefetch_successors).
    #[must_use]
    pub fn max_prefetch_successors(&self) -> usize {
        self.max_prefetch_successors
    }

    /// Override the per-engine speculative-prefetch fan-out cap.
    /// Defaults to [`DEFAULT_MAX_PREFETCH_SUCCESSORS`] (8). Lower it
    /// to throttle background fetches on memory-constrained hosts;
    /// raise it when graphs legitimately fan out widely. `0`
    /// effectively disables speculative prefetch (no successors will
    /// be fetched even with the per-node opt-in).
    pub fn set_max_prefetch_successors(&mut self, n: usize) {
        self.max_prefetch_successors = n;
    }

    /// Hard cap on the number of nodes this engine will accept via
    /// [`add_node`](Self::add_node). See
    /// [`set_max_workflow_nodes`](Self::set_max_workflow_nodes).
    #[must_use]
    pub fn max_workflow_nodes(&self) -> usize {
        self.max_workflow_nodes
    }

    /// Override the per-engine maximum graph size. Defaults to
    /// [`DEFAULT_MAX_WORKFLOW_NODES`] (500). `add_node` calls past
    /// the cap emit a `tracing::warn!` and are dropped.
    ///
    /// Raise for legitimately large workflows (code-generated DAGs,
    /// fan-out-of-fan-out aggregations); lower as a defence-in-depth
    /// measure for trust-boundary inputs.
    pub fn set_max_workflow_nodes(&mut self, n: usize) {
        self.max_workflow_nodes = n;
    }

    /// Per-node output size guard in bytes. See
    /// [`set_max_node_output_bytes`](Self::set_max_node_output_bytes).
    #[must_use]
    pub fn max_node_output_bytes(&self) -> usize {
        self.max_node_output_bytes
    }

    /// Override the per-node output size guard. Defaults to
    /// [`DEFAULT_MAX_NODE_OUTPUT_BYTES`] (5 MiB). Outputs over the
    /// limit get replaced with an `__error: true` envelope before
    /// they land in `results`, preventing one runaway node from
    /// cascading a multi-MB clone into every downstream
    /// `gathered_inputs` snapshot.
    ///
    /// Raise for nodes that legitimately produce large blobs (PDF
    /// rendering, image processing, log aggregation); lower as a
    /// defence-in-depth measure on memory-constrained hosts.
    pub fn set_max_node_output_bytes(&mut self, bytes: usize) {
        self.max_node_output_bytes = bytes;
    }

    /// Upper bound on Wasmtime fuel granted to any single dispatch.
    /// See [`set_max_fuel_per_node`](Self::set_max_fuel_per_node).
    #[must_use]
    pub fn max_fuel_per_node(&self) -> u64 {
        self.max_fuel_per_node
    }

    /// Override the per-node fuel ceiling. Defaults to
    /// [`DEFAULT_MAX_FUEL_PER_NODE`] (50 M, ~5 s of dense numeric
    /// work on the reference worker). Both per-node `max_fuel`
    /// overrides from the graph JSON and the module's declared fuel
    /// budget get clamped to this value before reaching the worker.
    ///
    /// Raise for compute-heavy workloads on dedicated workers; lower
    /// on shared infrastructure to bound the worst-case wall-clock
    /// any single dispatch can occupy.
    pub fn set_max_fuel_per_node(&mut self, max_fuel: u64) {
        self.max_fuel_per_node = max_fuel;
    }

    /// Replace the per-module rate-limit counter backing store.
    ///
    /// When `None` (the default), the engine routes
    /// `check_rate_limit` calls through the process-global in-memory
    /// `DashMap`. That's fine for a single-process deployment but
    /// resets on restart and doesn't share state across replicas.
    ///
    /// Wire a `Some(Arc<MyRedisStore>)` (or whatever your shared
    /// state is) for production fleets that need the cap to hold
    /// across rolling deploys and horizontal scaling. The trait
    /// surface is [`talos_workflow_engine_core::RateLimitStore`].
    /// Failure mode is **fail-open**: a store-side error logs a
    /// warning and allows the dispatch — see the trait docstring.
    pub fn set_rate_limit_store(
        &mut self,
        store: Arc<dyn talos_workflow_engine_core::RateLimitStore>,
    ) {
        self.rate_limit_store = Some(store);
    }

    /// Persist a [`CancellationToken`](tokio_util::sync::CancellationToken)
    /// on the engine. The non-`_cancellable` run methods
    /// ([`run_with_transport`](Self::run_with_transport),
    /// [`run_with_seed_with_transport`](Self::run_with_seed_with_transport))
    /// consult it before each dispatch and short-circuit with
    /// [`crate::WorkflowEngineError::Cancelled`] if it fires.
    ///
    /// Inherits through [`AdapterSet`] so sub-workflow loops
    /// (`AgentLoop`, `ReActLoop`, `Ensemble`, `ReflectiveRetry`,
    /// `Judge`, `LlmDispatch`, etc.) see the same cancel signal as
    /// the parent — cancelling a parent token aborts every running
    /// sub-workflow at the next dispatch boundary, not just the
    /// outer reactor.
    ///
    /// Pass `None` to clear a previously-set token. The
    /// `_cancellable` variants
    /// ([`run_with_transport_cancellable`](Self::run_with_transport_cancellable),
    /// [`run_with_seed_with_transport_cancellable`](Self::run_with_seed_with_transport_cancellable))
    /// take a token as a parameter and ignore this field —
    /// the parameter wins by design so a one-off run can override
    /// the engine's persistent token.
    pub fn set_cancellation_token(&mut self, token: Option<tokio_util::sync::CancellationToken>) {
        self.cancellation_token = token;
    }

    /// The engine-level cancellation token if set via
    /// [`set_cancellation_token`](Self::set_cancellation_token).
    /// Cloned (cheap — `CancellationToken` is itself an `Arc`
    /// internally).
    #[must_use]
    pub fn cancellation_token(&self) -> Option<tokio_util::sync::CancellationToken> {
        self.cancellation_token.clone()
    }

    /// Recursion-depth ceiling for sub-workflow dispatch. See
    /// [`set_max_subflow_depth`](Self::set_max_subflow_depth).
    #[must_use]
    pub fn max_subflow_depth(&self) -> usize {
        self.max_subflow_depth
    }

    /// Override the sub-workflow recursion-depth ceiling. Defaults
    /// to [`DEFAULT_MAX_SUBFLOW_DEPTH`] (16). Every sub-workflow
    /// handler (`Judge`, `Ensemble`, `AgentLoop`, etc.) hydrates a
    /// child engine via [`AdapterSet::into_engine_with_graph`],
    /// which checks the depth before doing any work and returns
    /// [`crate::WorkflowEngineError::SubflowRecursionLimit`] if the
    /// next dispatch would exceed the cap.
    ///
    /// Raise for genuinely-deep compositions; lower as a defence-
    /// in-depth measure for trust-boundary inputs.
    pub fn set_max_subflow_depth(&mut self, depth: usize) {
        self.max_subflow_depth = depth;
    }

    /// The sub-workflow dispatch depth this engine is operating at.
    /// `0` for top-level engines; `N` for engines hydrated `N`
    /// sub-workflow levels below the root. Useful for tests
    /// asserting on dispatch chain shape.
    #[must_use]
    pub fn current_subflow_depth(&self) -> usize {
        self.current_subflow_depth
    }

    /// Override the per-execution sandbox root.
    ///
    /// * `Some(path)` — every execution creates `<path>/<execution_id>`
    ///   at run-start and tears it down at run-end (RAII cleanup runs
    ///   even on panic). `<path>` itself is created with
    ///   [`std::fs::create_dir_all`] if missing — operators supply a
    ///   writable directory at startup.
    /// * `None` — sandbox creation is skipped entirely. Useful on
    ///   read-only filesystems, Windows without a writable `/tmp`
    ///   equivalent, or locked-down container environments. Modules
    ///   that request filesystem scratch space will observe `None` and
    ///   fall back to in-memory paths.
    ///
    /// The default is `Some(`[`default_sandbox_root()`](crate::default_sandbox_root)`.to_path_buf())` —
    /// the platform's `<tmp>/workflow-engine-sandboxes`. The Linux/macOS-only
    /// [`DEFAULT_SANDBOX_ROOT`](crate::DEFAULT_SANDBOX_ROOT) constant
    /// is deprecated; new code should reference the function form.
    pub fn set_sandbox_root(&mut self, root: Option<std::path::PathBuf>) {
        self.sandbox_root = root;
    }

    /// Replace the default approval gate. Out-of-tree consumers plug
    /// in their own impl (auto-approve for tests, a remote
    /// approval service for `SaaS` deployments).
    pub fn set_approval_gate(&mut self, gate: Arc<dyn talos_workflow_engine_core::ApprovalGate>) {
        self.approval_gate = Some(gate);
    }

    /// Replace the default module-execution store. Consumers that
    /// don't have a Postgres-backed module store plug in their own
    /// impl (capture, append log, no-op) here.
    pub fn set_module_execution_store(
        &mut self,
        store: Arc<dyn talos_workflow_engine_core::ModuleExecutionStore>,
    ) {
        self.module_execution_store = Some(store);
    }

    /// Replace the default module fetcher. Consumers plug in whatever
    /// backing store they prefer (Postgres catalog, OCI registry,
    /// in-memory test map) behind the [`ModuleFetcher`] trait. A
    /// downstream application typically wires a registry-backed
    /// default via its own engine-builder helper; direct users of
    /// this crate call `set_module_fetcher` themselves.
    pub fn set_module_fetcher(&mut self, fetcher: Arc<dyn ModuleFetcher>) {
        self.module_fetcher = Some(fetcher);
    }

    /// Replace the default execution-event sink. Tests use this to
    /// inject an in-memory capture or a no-op sink so dispatch does not
    /// depend on a Postgres pool. In-tree production callers using
    /// `with_services` / `with_registry` get a Postgres-backed default.
    pub fn set_event_sink(&mut self, sink: Arc<dyn EventSink>) {
        self.event_sink = Some(sink);
    }

    /// Replace the default post-completion hook. Tests use this to
    /// capture per-node outputs without exercising fuel rollup or
    /// actor-memory persistence.
    pub fn set_node_hook(&mut self, hook: Arc<dyn NodeLifecycleHook>) {
        self.node_hook = Some(hook);
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
            secret_envelope: self.secret_envelope.clone(),
            user_id: self.user_id,
            actor_id: self.actor_id,
            dry_run: self.dry_run,
            max_llm_tier: self.max_llm_tier,
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

    /// Populate this engine's graph from a parsed React-Flow JSON
    /// value. Accepts `&Value` so callers holding a pre-parsed graph
    /// (cached sub-workflow map, [`WorkflowGraphStore`] return) don't
    /// pay a second `serde_json::from_str`; callers holding a raw
    /// string parse once at their boundary before calling.
    ///
    /// The full wire shape is documented in
    /// [`docs/graph-json-schema.md`](https://github.com/aegix-dev/talos-workflow-engine/blob/main/docs/graph-json-schema.md).
    /// Summary: an object with `nodes: []` + `edges: []` + optional
    /// `execution_timeout_secs`. Each node carries `id` (UUID), an
    /// optional module `type` / built-in `kind` discriminator, an
    /// optional per-kind `data` payload, and retry/skip hints. Each
    /// edge carries `source` / `target` plus optional `sourceHandle`,
    /// `targetHandle`, and `logic` condition.
    ///
    /// Optional `execution_timeout_secs` at the graph root overrides
    /// the default 300 s timeout. Nodes with no resolvable
    /// `module_id` (non-UUID `type` and no `data.moduleId`) are
    /// silently skipped — the engine treats them as presentation-
    /// only annotations, matching the React Flow frontend's
    /// behavior.
    ///
    /// This replaced the pre-extraction `from_graph_json` associated
    /// function that took `Arc<ModuleRegistry>` directly. Call sites
    /// now chain `self.new_subengine().load_from_graph_json(&g)?;`
    /// which decouples the engine from any single concrete adapter
    /// type.
    ///
    /// [`WorkflowGraphStore`]: talos_workflow_engine_core::WorkflowGraphStore
    pub fn load_from_graph_json(
        &mut self,
        graph: &JsonValue,
    ) -> Result<(), crate::WorkflowEngineError> {
        self.parse_graph_document(graph)
    }

    /// Replace the default graph store. Consumers plug in whatever
    /// backing store resolves sub-workflow graph JSON — Postgres,
    /// S3, an in-memory map for tests — behind the
    /// [`WorkflowGraphStore`] trait. A downstream application
    /// typically wires a Postgres-backed default in its own
    /// engine-builder helper; direct users of this crate call this
    /// method themselves.
    pub fn set_graph_store(&mut self, store: Arc<dyn WorkflowGraphStore>) {
        self.graph_store = Some(store);
    }

    /// Wire a [`talos_workflow_engine_core::SubworkflowActorContextResolver`]
    /// so cross-actor sub-workflow dispatches inherit the
    /// *sub-workflow's bound actor's* memories under
    /// `__actor_context__`, instead of the sub-engine running with no
    /// context (and silently degrading `INJECT_CONTEXT`-driven LLM nodes).
    /// Optional — without it, sub-workflows behave as before this hook
    /// existed.
    pub fn set_sub_actor_context_resolver(
        &mut self,
        resolver: Arc<dyn talos_workflow_engine_core::SubworkflowActorContextResolver>,
    ) {
        self.sub_actor_context_resolver = Some(resolver);
    }

    /// Replace the default secrets resolver. Consumers that don't
    /// have a purpose-built secrets manager plug in their own impl
    /// here. Callers using `with_services` / `with_services_and_resolver`
    /// already have a default and don't need this.
    pub fn set_secrets_resolver(&mut self, resolver: Arc<dyn SecretsResolver>) {
        self.secrets_resolver = Some(resolver);
    }

    /// Replace the default expression evaluator (used for edge
    /// conditions, retry-delay expressions, and `Synthesize` node
    /// expressions). In production wraps a `rhai::Engine` with sandbox
    /// limits; tests plug in a no-op or a controlled mock.
    pub fn set_expression_evaluator(
        &mut self,
        evaluator: Arc<dyn talos_workflow_engine_core::ExpressionEvaluator>,
    ) {
        self.expression_evaluator = Some(evaluator);
    }

    /// Replace the default output sanitizer (applied to stored node
    /// outputs + error messages before DB persist). Production
    /// deployments typically wire a DLP-aware impl with a policy
    /// selector (for example, `provider=builtin | external | none`);
    /// tests can opt out via a passthrough impl.
    pub fn set_output_sanitizer(
        &mut self,
        sanitizer: Arc<dyn talos_workflow_engine_core::OutputSanitizer>,
    ) {
        self.output_sanitizer = Some(sanitizer);
    }

    /// Replace the default retry classifier (maps dispatch error
    /// strings to a class tag + transient/permanent decision). In
    /// production wraps `retry_intelligence`'s heuristics.
    pub fn set_retry_classifier(
        &mut self,
        classifier: Arc<dyn talos_workflow_engine_core::RetryClassifier>,
    ) {
        self.retry_classifier = Some(classifier);
    }

    /// Set the actor ID that owns this execution. Threaded into every
    /// `DispatchJob` so workers can route agent-memory `__memory_write__`
    /// protocol fields (and similar actor-scoped side effects) back to
    /// the correct rows. Distinct from
    /// [`set_user_id`](Self::set_user_id) — actors are a layer above
    /// users and not every execution has one. Skip on test paths.
    pub fn set_actor_id(&mut self, id: Uuid) {
        self.actor_id = Some(id);
    }

    /// Set the owning user ID used for per-user secret resolution and
    /// module-artifact cache scoping. **Required** for any run that
    /// dispatches to a [`ModuleFetcher`] — the engine refuses to
    /// dispatch a node without one rather than risk a cross-tenant
    /// artifact resolution. Controller-side builders set this
    /// automatically from the request context; out-of-tree consumers
    /// call it directly before [`run_with_transport`](Self::run_with_transport).
    pub fn set_user_id(&mut self, id: Uuid) {
        self.user_id = Some(id);
    }

    /// Snapshot of the configured event sink. Useful when a consumer
    /// builds a `NodeDispatcher` on the fly and needs to thread the
    /// engine's sink through it.
    #[must_use]
    pub fn event_sink_arc(&self) -> Option<Arc<dyn EventSink>> {
        self.event_sink.clone()
    }

    /// Snapshot of the configured retry classifier.
    #[must_use]
    pub fn retry_classifier_arc(
        &self,
    ) -> Option<Arc<dyn talos_workflow_engine_core::RetryClassifier>> {
        self.retry_classifier.clone()
    }

    /// Snapshot of the configured expression evaluator.
    #[must_use]
    pub fn expression_evaluator_arc(
        &self,
    ) -> Option<Arc<dyn talos_workflow_engine_core::ExpressionEvaluator>> {
        self.expression_evaluator.clone()
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

    fn eval_json(&self, expression: &str, context: &JsonValue) -> Result<JsonValue, String> {
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

    /// Set the **definition** id of the workflow this engine is
    /// running. Distinct from `execution_id` (a per-run UUID): the
    /// workflow id is stable across every run of the same workflow
    /// definition and is what cost / metrics / audit rollups should
    /// attribute against. Threaded into
    /// [`NodeLifecycleHook::on_node_completed`] via
    /// [`NodeCompletionContext::workflow_id`].
    ///
    /// Unset engines fall back to the per-run `execution_id` for
    /// attribution — works, but conflates per-run rollups with
    /// per-workflow rollups. Set this when you have a stable workflow
    /// row in your storage layer.
    ///
    /// [`NodeCompletionContext::workflow_id`]: talos_workflow_engine_core::NodeCompletionContext::workflow_id
    pub fn set_workflow_id(&mut self, id: Uuid) {
        self.workflow_id = Some(id);
    }

    /// Inject an actor-memory context blob that the engine merges into
    /// every node's input under the reserved key `__actor_context__`.
    ///
    /// Use this when an actor (a long-lived entity with persistent
    /// memory: persona, learned preferences, conversational history,
    /// …) owns the execution and downstream LLM nodes need that
    /// context without per-workflow plumbing. The expected shape is a
    /// JSON object — at minimum `{"actor_id": "...", "memories": [...]}`
    /// — but the engine doesn't validate; it just forwards.
    ///
    /// Skip on plain test harnesses or executions with no actor.
    pub fn set_actor_context(&mut self, context: serde_json::Value) {
        self.actor_context = Some(context);
    }

    /// Enable dry-run mode for this engine.
    ///
    /// When set, every dispatched [`DispatchJob`](talos_workflow_engine_core::DispatchJob) carries
    /// [`DispatchJob::dry_run = true`](talos_workflow_engine_core::DispatchJob::dry_run).
    /// What that means is the **dispatcher**'s decision; the reference
    /// NATS dispatcher tells the worker to mock non-GET HTTP requests,
    /// webhooks, and messaging calls so the workflow can run end-to-
    /// end without producing externally-visible side effects. A
    /// custom dispatcher that ignores the field will still execute
    /// normally — propagation is the engine's promise; honouring it
    /// is the dispatcher's.
    ///
    /// Common use: pre-merge "preview" runs in a workflow editor.
    pub fn set_dry_run(&mut self, v: bool) {
        self.dry_run = v;
    }

    /// Stamp the LLM tier ceiling on this engine. Propagated to every
    /// `DispatchJob` built during execution. Callers should set this
    /// from `actors.max_llm_tier` before calling `run()` / `run_with_seed()`.
    pub fn set_max_llm_tier(&mut self, tier: talos_workflow_engine_core::LlmTier) {
        self.max_llm_tier = tier;
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
    /// in-protocol integrity gate independent of the JobRequest
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
            return talos_workflow_job_protocol::EncryptedSecrets::default();
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

    /// Collect all statically-known sub-workflow IDs from `node_meta` and batch-fetch
    /// their `graph_json` in a single query. Populates `self.sub_workflow_cache`.
    ///
    /// Called once at the start of `run()` / `run_with_seed()` to eliminate N+1 queries
    /// during node dispatch. Nodes whose workflow IDs are resolved at runtime
    /// (`DynamicDispatch`, `CapabilityDispatch`) will fall back to individual queries
    /// via `get_sub_workflow_graph()` on cache miss.
    async fn populate_sub_workflow_cache(&mut self) {
        let (store, user_id) = match (self.graph_store.as_ref(), self.user_id) {
            (Some(s), Some(u)) => (s, u),
            _ => return, // No graph store or no user_id — nothing to prefetch.
        };

        // Walk all node_meta entries and collect every referenced workflow UUID.
        let mut ids: HashSet<Uuid> = HashSet::new();
        for (_, _, kind) in self.node_meta.values() {
            match kind {
                Some(SystemNodeKind::SubWorkflow { workflow_id, .. }) => {
                    ids.insert(*workflow_id);
                }
                #[cfg(feature = "llm-primitives")]
                Some(SystemNodeKind::AgentLoop {
                    body_workflow_id, ..
                }) => {
                    ids.insert(*body_workflow_id);
                }
                #[cfg(feature = "llm-primitives")]
                Some(SystemNodeKind::Judge {
                    judge_workflow_id, ..
                }) => {
                    ids.insert(*judge_workflow_id);
                }
                #[cfg(feature = "llm-primitives")]
                Some(SystemNodeKind::Ensemble {
                    child_workflow_id,
                    judge_workflow_id,
                    ..
                }) => {
                    ids.insert(*child_workflow_id);
                    if let Some(jid) = judge_workflow_id {
                        ids.insert(*jid);
                    }
                }
                #[cfg(feature = "llm-primitives")]
                Some(SystemNodeKind::ReflectiveRetry {
                    child_workflow_id,
                    reflection_workflow_id,
                    ..
                }) => {
                    ids.insert(*child_workflow_id);
                    ids.insert(*reflection_workflow_id);
                }
                #[cfg(feature = "llm-primitives")]
                Some(SystemNodeKind::LlmDispatch {
                    classifier_workflow_id,
                    routes,
                    fallback_workflow_id,
                    ..
                }) => {
                    ids.insert(*classifier_workflow_id);
                    for wf_id in routes.values() {
                        ids.insert(*wf_id);
                    }
                    if let Some(fb) = fallback_workflow_id {
                        ids.insert(*fb);
                    }
                }
                #[cfg(feature = "llm-primitives")]
                Some(SystemNodeKind::ReActLoop {
                    body_workflow_id, ..
                }) => {
                    ids.insert(*body_workflow_id);
                }
                _ => {}
            }
        }

        // Remove nil UUIDs (used as sentinel for missing workflow_id).
        ids.remove(&Uuid::nil());

        if ids.is_empty() {
            return;
        }

        let id_vec: Vec<Uuid> = ids.into_iter().collect();
        tracing::info!(
            count = id_vec.len(),
            "Populating sub-workflow cache with batch query"
        );

        let rows = match store.get_graphs(&id_vec, user_id).await {
            Ok(map) => map,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to batch-fetch sub-workflow graphs — falling back to per-node queries"
                );
                return;
            }
        };

        for (wf_id, graph_json) in rows {
            self.sub_workflow_cache.insert(wf_id, graph_json);
        }

        tracing::info!(
            cached = self.sub_workflow_cache.len(),
            "Sub-workflow cache populated"
        );
    }

    /// Look up a sub-workflow's graph JSON, checking the pre-populated cache first.
    /// Falls back to an individual DB query on cache miss (e.g., `DynamicDispatch`
    /// targets that are resolved at runtime).
    pub(crate) async fn get_sub_workflow_graph(
        &self,
        sub_wf_id: Uuid,
        user_id: Uuid,
    ) -> Option<JsonValue> {
        // Fast path: cache hit.
        if let Some(cached) = self.sub_workflow_cache.get(&sub_wf_id) {
            return Some(cached.clone());
        }
        // Cache miss — fall back to an individual query via the trait.
        tracing::debug!(
            workflow_id = %sub_wf_id,
            "Sub-workflow cache miss — falling back to individual query"
        );
        let store = self.graph_store.as_ref()?;
        match store.get_graph(sub_wf_id, user_id).await {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(error = %e, "sub-workflow graph query failed");
                None
            }
        }
    }

    /// Load a workflow graph from a JSON string (React Flow format).
    ///
    /// Parses nodes and edges from the JSON and populates the internal graph.
    pub async fn load_graph_from_json(
        &mut self,
        graph_json: &str,
    ) -> Result<(), crate::WorkflowEngineError> {
        let graph: serde_json::Value = serde_json::from_str(graph_json)
            .map_err(|e| crate::WorkflowEngineError::GraphJson(e.into()))?;

        // Full synchronous parse — nodes, system nodes, reserved-key
        // lifts, edges, execution_timeout_secs. The sync entry point
        // `load_from_graph_json` shares this exact parser, so the two
        // public methods never diverge.
        self.parse_graph_document(&graph)?;
        // Async follow-ups: rate-limit pre-load + sub-workflow graph
        // prefetch. Kept out of `parse_graph_document` so the sync entry
        // point doesn't need a runtime.
        self.preload_rate_limits_and_subflows().await;
        Ok(())
    }

    /// Async post-parse: batch-load per-module rate limits and
    /// pre-fetch all sub-workflow graphs referenced by system nodes.
    /// Eliminates N+1 queries during node dispatch.
    async fn preload_rate_limits_and_subflows(&mut self) {
        if let Some(ref fetcher) = self.module_fetcher {
            let module_ids: Vec<Uuid> = self
                .node_meta
                .values()
                .filter_map(|(mid, _, _)| *mid)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            if !module_ids.is_empty() {
                let rate_limits = fetcher.load_rate_limits(&module_ids).await;
                for (id, limit) in rate_limits {
                    self.rate_limits.insert(id, limit);
                }
                if !self.rate_limits.is_empty() {
                    tracing::info!(
                        rate_limited_modules = self.rate_limits.len(),
                        "Loaded module rate limits for workflow",
                    );
                }
            }
        }
        self.populate_sub_workflow_cache().await;
    }

    /// Single authoritative synchronous parser for React-Flow graph JSON.
    ///
    /// Accepts both the `&Value` entry point ([`load_from_graph_json`])
    /// and the `&str` entry point ([`load_graph_from_json`], after JSON
    /// parsing) delegate here, so the two public methods see exactly the
    /// same parser semantics:
    ///
    /// * Module nodes (`type = <uuid>` or `data.moduleId = <uuid>`) and
    ///   system nodes (`type = "system:<kind>"` or an explicit `kind`
    ///   field) are both recognised.
    /// * `execution_timeout_secs` at the graph root overrides the
    ///   default.
    /// * `skip_condition` / `continue_on_error` are lifted into reserved
    ///   `__skip_condition` / `__continue_on_error` node-config keys.
    /// * Edges carry `sourceHandle` / `targetHandle` / `condition` /
    ///   `edge_type` when present.
    ///
    /// Returns [`crate::WorkflowEngineError::EmptyGraph`] when `nodes`
    /// is missing or empty (the engine refuses to run a graph with no
    /// work). Parse-time failures surface as
    /// [`crate::WorkflowEngineError::GraphJson`]; other load-time
    /// rejections surface as
    /// [`crate::WorkflowEngineError::LoadGraph`].
    ///
    /// Async follow-ups (rate-limit pre-load, sub-workflow graph
    /// prefetch) are intentionally out of scope — see
    /// [`load_graph_from_json`] for where they run.
    ///
    /// [`load_from_graph_json`]: Self::load_from_graph_json
    /// [`load_graph_from_json`]: Self::load_graph_from_json
    pub(crate) fn parse_graph_document(
        &mut self,
        graph: &JsonValue,
    ) -> Result<(), crate::WorkflowEngineError> {
        let empty_vec = vec![];
        let nodes = graph
            .get("nodes")
            .and_then(|n| n.as_array())
            .unwrap_or(&empty_vec);

        if nodes.is_empty() {
            return Err(crate::WorkflowEngineError::EmptyGraph);
        }

        if let Some(timeout) = graph
            .get("execution_timeout_secs")
            .and_then(JsonValue::as_u64)
        {
            self.execution_timeout_secs = timeout;
        }

        // Map RF node ID → unique engine node UUID. The node_id in the
        // engine graph MUST be unique per node (not per module) to
        // allow the same module in multiple nodes without creating
        // false cycle detections.
        let mut rf_to_node: HashMap<String, Uuid> = HashMap::new();

        for node in nodes {
            let rf_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let module_id_str = node
                .get("type")
                .and_then(|v| v.as_str())
                .filter(|s| Uuid::parse_str(s).is_ok())
                .or_else(|| {
                    node.get("data")
                        .and_then(|d| d.get("moduleId"))
                        .and_then(|v| v.as_str())
                });
            if let Some(module_id_str) = module_id_str {
                if let Ok(module_id) = Uuid::parse_str(module_id_str) {
                    // Reuse RF ID if it's a UUID, else derive a
                    // deterministic UUID from the string via SHA-256.
                    let node_id = Uuid::parse_str(rf_id).unwrap_or_else(|_| {
                        use sha2::{Digest, Sha256};
                        let hash = Sha256::digest(rf_id.as_bytes());
                        let mut bytes = [0u8; 16];
                        bytes.copy_from_slice(&hash[..16]);
                        Uuid::from_bytes(bytes)
                    });
                    rf_to_node.insert(rf_id.to_string(), node_id);
                    self.node_labels.insert(node_id, rf_id.to_string());

                    if let Some(data) = node.get("data").cloned() {
                        if data.is_object()
                            && !data.as_object().map(|m| m.is_empty()).unwrap_or(true)
                        {
                            self.node_configs.insert(node_id, data.clone());
                        }
                        // skip_condition → reserved `__skip_condition`.
                        if let Some(skip_cond) = data
                            .get("skip_condition")
                            .and_then(|v| v.as_str())
                            .or_else(|| node.get("skip_condition").and_then(|v| v.as_str()))
                            .or_else(|| {
                                node.get("config")
                                    .and_then(|c| c.get("skip_condition"))
                                    .and_then(|v| v.as_str())
                            })
                        {
                            let entry = self
                                .node_configs
                                .entry(node_id)
                                .or_insert_with(|| serde_json::json!({}));
                            entry.as_object_mut().map(|m| {
                                m.insert(
                                    "__skip_condition".to_string(),
                                    serde_json::json!(skip_cond),
                                )
                            });
                        }
                        // continue_on_error → reserved `__continue_on_error`.
                        if data
                            .get("continue_on_error")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                            || node
                                .get("continue_on_error")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false)
                        {
                            let entry = self
                                .node_configs
                                .entry(node_id)
                                .or_insert_with(|| serde_json::json!({}));
                            entry.as_object_mut().map(|m| {
                                m.insert("__continue_on_error".to_string(), serde_json::json!(true))
                            });
                        }
                    } else {
                        // Node has no "data" — check top-level and config.skip_condition.
                        if let Some(skip_cond) = node
                            .get("skip_condition")
                            .and_then(|v| v.as_str())
                            .or_else(|| {
                                node.get("config")
                                    .and_then(|c| c.get("skip_condition"))
                                    .and_then(|v| v.as_str())
                            })
                        {
                            let entry = self
                                .node_configs
                                .entry(node_id)
                                .or_insert_with(|| serde_json::json!({}));
                            entry.as_object_mut().map(|m| {
                                m.insert(
                                    "__skip_condition".to_string(),
                                    serde_json::json!(skip_cond),
                                )
                            });
                        }
                        if let Some(true) = node
                            .get("continue_on_error")
                            .and_then(|v| v.as_bool())
                            .or_else(|| {
                                node.get("config")
                                    .and_then(|c| c.get("continue_on_error"))
                                    .and_then(|v| v.as_bool())
                            })
                        {
                            let entry = self
                                .node_configs
                                .entry(node_id)
                                .or_insert_with(|| serde_json::json!({}));
                            entry.as_object_mut().map(|m| {
                                m.insert("__continue_on_error".to_string(), serde_json::json!(true))
                            });
                        }
                    }

                    let kind = node
                        .get("kind")
                        .and_then(|k| k.as_str())
                        .and_then(|k| parse_system_node_kind(k, node));
                    let retry_policy = read_node_retry_policy_with_actor_cap(node, self.actor_id);
                    self.add_node(node_id, Some(module_id), retry_policy, kind);
                    let node_timeout_secs: Option<u64> = node
                        .get("data")
                        .and_then(|d| d.get("timeout_secs"))
                        .or_else(|| node.get("timeout_secs"))
                        .and_then(|v| v.as_u64());
                    if let Some(t) = node_timeout_secs {
                        self.node_timeouts.insert(node_id, t);
                    }
                }
            } else if node
                .get("type")
                .and_then(|v| v.as_str())
                .map(|s| s.starts_with("system:"))
                .unwrap_or(false)
            {
                // System node: no module_id, but has a kind.
                let node_id = Uuid::parse_str(rf_id).unwrap_or_else(|_| {
                    use sha2::{Digest, Sha256};
                    let hash = Sha256::digest(rf_id.as_bytes());
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&hash[..16]);
                    Uuid::from_bytes(bytes)
                });
                rf_to_node.insert(rf_id.to_string(), node_id);
                self.node_labels.insert(node_id, rf_id.to_string());

                if let Some(data) = node.get("data").cloned() {
                    if data.is_object() && !data.as_object().map(|m| m.is_empty()).unwrap_or(true) {
                        self.node_configs.insert(node_id, data.clone());
                    }
                    if let Some(skip_cond) = data
                        .get("skip_condition")
                        .and_then(|v| v.as_str())
                        .or_else(|| node.get("skip_condition").and_then(|v| v.as_str()))
                    {
                        let entry = self
                            .node_configs
                            .entry(node_id)
                            .or_insert_with(|| serde_json::json!({}));
                        entry.as_object_mut().map(|m| {
                            m.insert("__skip_condition".to_string(), serde_json::json!(skip_cond))
                        });
                    }
                    if data
                        .get("continue_on_error")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                        || node
                            .get("continue_on_error")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                    {
                        let entry = self
                            .node_configs
                            .entry(node_id)
                            .or_insert_with(|| serde_json::json!({}));
                        entry.as_object_mut().map(|m| {
                            m.insert("__continue_on_error".to_string(), serde_json::json!(true))
                        });
                    }
                }

                // Derive kind from explicit "kind" field first, then fall back
                // to the "system:" type suffix — handles nodes emitted by
                // builders that omit the "kind" field redundantly.
                let kind_str: Option<&str> =
                    node.get("kind").and_then(|k| k.as_str()).or_else(|| {
                        node.get("type")
                            .and_then(|t| t.as_str())
                            .and_then(|t| t.strip_prefix("system:"))
                    });
                let kind = kind_str.and_then(|k| parse_system_node_kind(k, node));
                self.add_node(node_id, None, None, kind);
            }
        }

        let empty_edges = vec![];
        let edges = graph
            .get("edges")
            .and_then(|e| e.as_array())
            .unwrap_or(&empty_edges);

        for edge in edges {
            let src_rf = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let tgt_rf = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
            if let (Some(&src), Some(&tgt)) = (rf_to_node.get(src_rf), rf_to_node.get(tgt_rf)) {
                let _ = self.add_edge(
                    src,
                    tgt,
                    EdgeLogic {
                        source_handle: edge
                            .get("sourceHandle")
                            .and_then(|v| v.as_str())
                            .unwrap_or("output")
                            .to_string(),
                        target_handle: edge
                            .get("targetHandle")
                            .and_then(|v| v.as_str())
                            .unwrap_or("input")
                            .to_string(),
                        mapping: None,
                        condition: edge
                            .get("condition")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        edge_type: edge
                            .get("edge_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("default")
                            .to_string(),
                    },
                );
            }
        }

        Ok(())
    }

    // Checkpoint load is handled by the consumer's `CheckpointStore`
    // impl (see `talos_workflow_engine_core::CheckpointStore`). Callers
    // invoke `store.load(id)` themselves and feed the result into
    // `run_with_seed`.

    /// Extract module UUIDs referenced in a `graph_json` string.
    ///
    /// Useful for consumers that maintain a workflow → module junction
    /// table in their own storage.
    pub fn extract_module_ids(graph_json: &str) -> Vec<Uuid> {
        let graph: serde_json::Value = match serde_json::from_str(graph_json) {
            Ok(v) => v,
            Err(_) => return vec![],
        };

        let empty_vec = vec![];
        let nodes = graph
            .get("nodes")
            .and_then(|n| n.as_array())
            .unwrap_or(&empty_vec);

        // Preallocate to nodes.len() — most nodes have a module_id,
        // so the eventual length is close to nodes.len(). Avoids the
        // repeated 2x reallocation cycle in graphs > 8 nodes.
        let mut module_ids = Vec::with_capacity(nodes.len());
        for node in nodes {
            let module_id_str = node
                .get("type")
                .and_then(|v| v.as_str())
                .filter(|s| Uuid::parse_str(s).is_ok())
                .or_else(|| {
                    node.get("data")
                        .and_then(|d| d.get("moduleId"))
                        .and_then(|v| v.as_str())
                });
            if let Some(id_str) = module_id_str {
                if let Ok(uuid) = Uuid::parse_str(id_str) {
                    module_ids.push(uuid);
                }
            }
        }
        module_ids.sort();
        module_ids.dedup();
        module_ids
    }

    /// Resolve the actual module UUID for a node.
    /// Nodes have their own unique IDs in the graph; the `module_id` (which WASM to load)
    /// is stored in `node_meta`. Falls back to `node_id` for backwards compatibility.
    pub(crate) fn resolve_module_id(&self, node_id: Uuid) -> Uuid {
        self.node_meta
            .get(&node_id)
            .and_then(|(mid, _, _)| *mid)
            .unwrap_or(node_id)
    }

    /// Add a node to the engine's graph.
    ///
    /// `id` is the engine-local node UUID; `module_id` is the
    /// resolved module to dispatch (or `None` for system-only
    /// nodes); `retry_policy` overrides the workflow-level default;
    /// `kind` carries the [`SystemNodeKind`] discriminator (or
    /// `None` for plain module nodes).
    ///
    /// Calls past [`max_workflow_nodes`](Self::max_workflow_nodes)
    /// emit a `tracing::warn!` and are silently dropped — by
    /// design, so a misbehaving graph generator can't exhaust
    /// memory before dispatch starts. Raise the cap via
    /// [`set_max_workflow_nodes`](Self::set_max_workflow_nodes) if
    /// the limit is too low for legitimate use.
    pub fn add_node(
        &mut self,
        id: Uuid,
        module_id: Option<Uuid>,
        retry_policy: Option<talos_workflow_engine_core::RetryPolicy>,
        kind: Option<SystemNodeKind>,
    ) {
        if self.graph.node_count() >= self.max_workflow_nodes {
            tracing::warn!(
                node_count = self.graph.node_count(),
                max = self.max_workflow_nodes,
                "Workflow graph exceeds maximum node count — ignoring add_node"
            );
            return;
        }
        let idx = self.graph.add_node(id);
        self.node_map.insert(id, idx);
        self.node_meta.insert(id, (module_id, retry_policy, kind));
    }

    /// Add a directed edge between two nodes already present in the
    /// graph. Returns `Err(WorkflowEngineError::LoadGraph)` if either
    /// endpoint is unknown — typically a typo in the graph builder.
    #[allow(dead_code)]
    pub fn add_edge(
        &mut self,
        from: Uuid,
        to: Uuid,
        logic: EdgeLogic,
    ) -> Result<(), crate::WorkflowEngineError> {
        let from_idx = *self.node_map.get(&from).ok_or_else(|| {
            crate::WorkflowEngineError::load_graph(format!("Edge source node {} not found", from))
        })?;
        let to_idx = *self.node_map.get(&to).ok_or_else(|| {
            crate::WorkflowEngineError::load_graph(format!("Edge target node {} not found", to))
        })?;
        self.graph.add_edge(from_idx, to_idx, logic);
        Ok(())
    }

    /// Install a synthetic `__trigger__` root node that carries the
    /// caller-supplied trigger input, wiring it to every current root
    /// so root-level nodes execute with the trigger as their input.
    ///
    /// Idempotent: if a `__trigger__` node is already present (for
    /// instance because this method ran once before), its Uuid is
    /// reused and only missing trigger → root edges are added. That
    /// means repeat invocations with the same or an expanded graph
    /// produce the same wiring without stacking parallel triggers.
    ///
    /// Returns the Uuid of the trigger node so the caller can seed
    /// `initial_results` with it before dispatching the engine.
    ///
    /// Shared by [`execute_subworkflow_graph`](Self::execute_subworkflow_graph)
    /// (operating on a fresh sub-engine) and
    /// [`run_with_trigger_input_transport`](Self::run_with_trigger_input_transport)
    /// (operating on the top-level engine). Kept private so the
    /// `__trigger__` mechanism stays an implementation detail of the
    /// crate — future refactors can replace it with a native seeding
    /// path without a public-API break.
    fn ensure_trigger_node_wired_to_roots(&mut self) -> Uuid {
        // Reuse an existing synthetic trigger if one is already
        // registered. The label is the authoritative marker — the
        // Uuid itself is engine-generated and opaque to callers.
        let existing = self
            .node_labels
            .iter()
            .find(|(_, label)| label.as_str() == talos_workflow_engine_core::reserved_keys::TRIGGER)
            .map(|(uuid, _)| *uuid);

        let trigger_node_id = match existing {
            Some(id) => id,
            None => {
                let id = Uuid::new_v4();
                self.add_node(id, None, None, None);
                self.node_labels.insert(
                    id,
                    talos_workflow_engine_core::reserved_keys::TRIGGER.to_string(),
                );
                id
            }
        };

        // Roots are every node with zero incoming edges, excluding the
        // trigger itself. Collect root Uuids (not NodeIndices) so the
        // subsequent `add_edge` calls — which do their own index
        // lookup — stay correct if the graph is mutated between
        // iterations.
        let root_ids: Vec<Uuid> = self
            .graph
            .node_indices()
            .filter_map(|idx| {
                let id = self.graph[idx];
                if id == trigger_node_id {
                    return None;
                }
                let in_degree = self
                    .graph
                    .neighbors_directed(idx, Direction::Incoming)
                    .count();
                if in_degree == 0 {
                    Some(id)
                } else {
                    None
                }
            })
            .collect();

        for root_id in root_ids {
            // `add_edge` is a no-op-ish idempotent operation only for
            // structurally distinct edges; petgraph does allow
            // duplicates. On a fresh trigger node every `add_edge`
            // adds a new edge exactly once. On a reused trigger node,
            // we only add an edge if one doesn't already exist —
            // otherwise repeat invocations would stack parallel edges
            // from trigger → the same root, and the scheduler would
            // see the root with in-degree > 1 (breaking the root
            // identification on the next call).
            let trigger_idx = self.node_map[&trigger_node_id];
            let root_idx = self.node_map[&root_id];
            let already_wired = self
                .graph
                .edges_connecting(trigger_idx, root_idx)
                .next()
                .is_some();
            if !already_wired {
                let _ = self.add_edge(
                    trigger_node_id,
                    root_id,
                    EdgeLogic {
                        source_handle: "output".to_string(),
                        target_handle: "input".to_string(),
                        mapping: None,
                        condition: None,
                        edge_type: "default".to_string(),
                    },
                );
            }
        }

        trigger_node_id
    }

    /// Unwrap engine wrapper from node output if present.
    /// Templates receive `{"config": ..., "input": ...}` and many echo it back.
    /// For inter-node data flow, we want the raw payload, not the engine wrapper.
    /// Collapse a completed sub-workflow's per-node results into a single output value.
    ///
    /// All sub-workflow invocation sites (judge, reflective-retry, ensemble, `sub_workflow`)
    /// need the same semantics; authoring a sub-workflow whose output is a shaped record
    /// (e.g. judge returning `{score, passed, reasoning, feedback}`) should "just work"
    /// regardless of how the sub-workflow graph is wired internally.
    ///
    /// Rules:
    /// - Nodes marked `__skipped` are dropped.
    /// - The synthetic `__trigger__` node is dropped.
    /// - Each remaining output is passed through `unwrap_output` to strip the engine
    ///   `{input, config, ...}` envelope.
    /// - If exactly one **terminal** node remains (a node with no outgoing edges inside
    ///   the sub-graph), its unwrapped output IS the collapsed value. Callers see the
    ///   record shape their sub-workflow returns, not a `{node_label: {...}}` wrap.
    /// - Otherwise (zero terminals, which means the graph is cyclic or empty, or
    ///   multiple terminals — a diamond without an explicit aggregator), fall back to a
    ///   label-keyed map so callers can still reach individual branches via
    ///   `output[label]`. Node-label collisions are deterministically resolved by
    ///   preferring terminal nodes (so shadowing a non-terminal is explicit).
    /// One-shot dispatch of an Ensemble system node.
    ///
    /// Runs `child_wf_id` `run_count` times with the same input, then applies
    /// the consensus strategy to pick a winner:
    /// - `first_pass`: first non-error result.
    /// - `best_of_n`: requires `judge_wf_id_opt`; scores each candidate via the
    ///   judge workflow and picks the highest score.
    /// - anything else ("`majority_vote`" / default): most common value at
    ///   `result`/`output` key (with an 8 KiB vote-key cap to bound memory).
    ///
    /// Output is enriched with `__ensemble_method__` and `__ensemble_size__`.
    pub async fn dispatch_ensemble(
        &self,
        inputs: JsonValue,
        child_wf_id: Uuid,
        run_count: u32,
        consensus_strategy: String,
        judge_wf_id_opt: Option<Uuid>,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
    ) -> JsonValue {
        let clean_input = if let Some(obj) = inputs.as_object() {
            let mut cleaned = obj.clone();
            cleaned.retain(|k, _| !k.starts_with("__"));
            serde_json::Value::Object(cleaned)
        } else {
            inputs
        };

        // 1. Run the child workflow N times. M6 (2026-05-28 review): the N runs
        // are INDEPENDENT (identical input), so run them CONCURRENTLY instead of
        // sequentially — pre-fix wall-clock was run_count × child-latency (a
        // 5-run ensemble of a 10s child took ~50s instead of ~10s). `buffered`
        // preserves run order so `first_pass` (picks the first non-error) and
        // the recorded metadata stay deterministic, and bounds concurrency at
        // MAX_CONCURRENT_NODE_DISPATCH so a large run_count (or nested
        // ensembles) can't stampede the worker fleet. The sibling `sub_workflow`
        // fan-out path was already parallel; ensemble had been missed.
        let candidate_futs = (0..run_count).map(|_i| {
            let input = clean_input.clone();
            let dispatcher = dispatcher.clone();
            let wsk = worker_shared_key.clone();
            async move {
                match self
                    .execute_subworkflow_graph(child_wf_id, input, dispatcher, wsk)
                    .await
                {
                    Ok(v) => v,
                    Err(e) => e.into_error_envelope("Ensemble child"),
                }
            }
        });
        let all_results: Vec<JsonValue> = futures::stream::iter(candidate_futs)
            .buffered(*MAX_CONCURRENT_NODE_DISPATCH)
            .collect()
            .await;

        // 2. Pick a winner via the consensus strategy.
        let consensus_output: JsonValue = match consensus_strategy.as_str() {
            "first_pass" => all_results
                .iter()
                .find(|r| !r.get("__error").and_then(|v| v.as_bool()).unwrap_or(false))
                .cloned()
                .unwrap_or_else(|| {
                    all_results.first().cloned().unwrap_or_else(|| {
                        serde_json::json!({
                            "__error": true,
                            "error_message": "All ensemble runs failed"
                        })
                    })
                }),
            "best_of_n" if judge_wf_id_opt.is_some() => {
                let judge_wf_id = judge_wf_id_opt.unwrap();
                let mut best_result: Option<JsonValue> = None;
                let mut best_score = f64::NEG_INFINITY;
                for candidate in &all_results {
                    if candidate
                        .get("__error")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    let judge_input = serde_json::json!({ "content": candidate, "rubric": "" });
                    if let Ok(collapsed) = self
                        .execute_subworkflow_graph(
                            judge_wf_id,
                            judge_input,
                            dispatcher.clone(),
                            worker_shared_key.clone(),
                        )
                        .await
                    {
                        let verdict = JudgeVerdict::from_collapsed(&collapsed);
                        if verdict.score > best_score {
                            best_score = verdict.score;
                            best_result = Some(candidate.clone());
                        }
                    }
                }
                let chosen = best_result.unwrap_or_else(|| {
                    all_results.first().cloned().unwrap_or_else(|| {
                        serde_json::json!({
                            "__error": true,
                            "error_message": "All best_of_n candidates failed"
                        })
                    })
                });
                Self::emit_quality_gate_event(
                    "ensemble_best_of_n",
                    best_score > f64::NEG_INFINITY,
                    if best_score > f64::NEG_INFINITY {
                        Some(best_score)
                    } else {
                        None
                    },
                    Some(run_count),
                    None,
                );
                chosen
            }
            _ => {
                // majority_vote: find most common value at result["result"] or result["output"].
                // Vote-key is capped at 8 KiB to bound memory when candidates are huge.
                let mut vote_counts: std::collections::HashMap<String, (usize, JsonValue)> =
                    std::collections::HashMap::new();
                const MAX_VOTE_KEY_BYTES: usize = 8_192;
                for r in &all_results {
                    if r.get("__error").and_then(|v| v.as_bool()).unwrap_or(false) {
                        continue;
                    }
                    let key_val = {
                        let s = r
                            .get("result")
                            .or_else(|| r.get("output"))
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| r.to_string());
                        if s.len() > MAX_VOTE_KEY_BYTES {
                            s[..MAX_VOTE_KEY_BYTES].to_string()
                        } else {
                            s
                        }
                    };
                    let entry = vote_counts.entry(key_val).or_insert((0, r.clone()));
                    entry.0 += 1;
                }
                vote_counts
                    .into_iter()
                    .max_by_key(|(_, (count, _))| *count)
                    .map(|(_, (_, best))| best)
                    .unwrap_or_else(|| {
                        all_results.first().cloned().unwrap_or_else(|| {
                            serde_json::json!({
                                "__error": true,
                                "error_message": "Ensemble majority_vote: all runs failed"
                            })
                        })
                    })
            }
        };

        // 3. Annotate with ensemble metadata.
        let mut out = if let Some(obj) = consensus_output.as_object() {
            obj.clone()
        } else {
            serde_json::Map::new()
        };
        out.insert(
            "__ensemble_method__".to_string(),
            serde_json::json!(consensus_strategy),
        );
        out.insert(
            "__ensemble_size__".to_string(),
            serde_json::json!(run_count),
        );
        serde_json::Value::Object(out)
    }

    /// One-shot dispatch of a `LlmDispatch` system node.
    ///
    /// Flow:
    /// 1. Run `classifier_wf_id` with the inbound inputs (stripped of `__*`).
    /// 2. Extract a class string from the classifier output (top-level
    ///    `class`, `output`, or `result` keys — whichever is present).
    /// 3. If the class matches a key in `routes`, run that route's workflow
    ///    with the same input. Otherwise run `fallback_wf_id` (if set),
    ///    passing the unmatched class as `__unmatched_class__`.
    ///
    /// The returned output always carries `__dispatched_class__` and
    /// `__dispatched_workflow_id__` for trace observability.
    pub async fn dispatch_llm_dispatch(
        &self,
        inputs: JsonValue,
        classifier_wf_id: Uuid,
        routes: std::collections::HashMap<String, Uuid>,
        fallback_wf_id: Option<Uuid>,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
    ) -> JsonValue {
        let clean_input = if let Some(obj) = inputs.as_object() {
            let mut cleaned = obj.clone();
            cleaned.retain(|k, _| !k.starts_with("__"));
            serde_json::Value::Object(cleaned)
        } else {
            inputs
        };

        // 1. Run classifier. Distinguish 3 failure modes rather than
        // collapsing them into a single "empty class" message:
        //   a) classifier sub-workflow itself failed (DB, build, exec error)
        //   b) classifier ran but returned no recognised class field
        //   c) classifier ran and returned an empty string
        let class_str = match self
            .execute_subworkflow_graph(
                classifier_wf_id,
                clean_input.clone(),
                dispatcher.clone(),
                worker_shared_key.clone(),
            )
            .await
        {
            Ok(out) => {
                let raw = out
                    .get("class")
                    .or_else(|| out.get("output"))
                    .or_else(|| out.get("result"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                match raw {
                    None => {
                        let keys: Vec<&String> = out
                            .as_object()
                            .map(|m| m.keys().collect())
                            .unwrap_or_default();
                        return serde_json::json!({
                            "__error": true,
                            "error_message": format!(
                                "LlmDispatch classifier output had no 'class', 'output', or 'result' \
                                 string field (saw keys: {:?}). The classifier sub-workflow must return \
                                 a string class label.",
                                keys
                            ),
                        });
                    }
                    Some(s) if s.is_empty() => {
                        return serde_json::json!({
                            "__error": true,
                            "error_message":
                                "LlmDispatch classifier returned an empty class string — \
                                 the classifier must produce a non-empty label.",
                        });
                    }
                    Some(s) => s,
                }
            }
            Err(e) => {
                // Preserve the classifier sub-workflow error detail under a
                // context-specific label so the caller can tell the difference
                // between "classifier failed" and "classifier returned bad data".
                return e.into_error_envelope("LlmDispatch classifier");
            }
        };

        // 2. Resolve the target workflow from routes or fallback.
        let (target_wf_id, input_for_target, is_fallback) = match routes.get(&class_str) {
            Some(&target) => (target, clean_input, false),
            None => match fallback_wf_id {
                Some(fb) => {
                    let mut fb_input = if let Some(obj) = clean_input.as_object() {
                        obj.clone()
                    } else {
                        serde_json::Map::new()
                    };
                    fb_input.insert(
                        "__unmatched_class__".to_string(),
                        serde_json::json!(class_str),
                    );
                    (fb, serde_json::Value::Object(fb_input), true)
                }
                None => {
                    let route_keys: Vec<&String> = routes.keys().collect();
                    return serde_json::json!({
                        "__error": true,
                        "error_message": format!(
                            "LLM dispatch: class '{}' not in routes {:?}",
                            class_str, route_keys
                        )
                    });
                }
            },
        };

        // 3. Execute the target workflow and annotate the result.
        let context_label = if is_fallback {
            "LlmDispatch fallback"
        } else {
            "LlmDispatch target"
        };
        match self
            .execute_subworkflow_graph(
                target_wf_id,
                input_for_target,
                dispatcher,
                worker_shared_key,
            )
            .await
        {
            Ok(target_out) => {
                let mut out = if let Some(obj) = target_out.as_object() {
                    obj.clone()
                } else {
                    let mut m = serde_json::Map::new();
                    m.insert("output".to_string(), target_out);
                    m
                };
                out.insert(
                    "__dispatched_class__".to_string(),
                    serde_json::json!(class_str),
                );
                out.insert(
                    "__dispatched_workflow_id__".to_string(),
                    serde_json::json!(target_wf_id.to_string()),
                );
                // Unified observability fields (parity with capability_dispatch
                // / expression_dispatch) — readers can pivot on these without
                // having to know the dispatcher kind ahead of time.
                out.insert(
                    "__dispatched_by".to_string(),
                    serde_json::json!("llm_dispatch"),
                );
                out.insert(
                    "__dispatch_branch__".to_string(),
                    serde_json::json!(class_str),
                );
                if is_fallback {
                    out.insert(
                        "__llm_dispatch_fallback".to_string(),
                        serde_json::json!(true),
                    );
                }
                serde_json::Value::Object(out)
            }
            Err(e) => e.into_error_envelope(context_label),
        }
    }

    /// One-shot dispatch of a ReflectiveRetry system node.
    ///
    /// Runs `child_wf_id` up to `max_retries` times. After each failure,
    /// invokes `reflection_wf_id` with `{input, error, attempt}`. The
    /// reflection workflow's returned fields are merged (non-`__` keys only)
    /// back into the child's input for the next attempt — the child adapts
    /// instead of blindly re-running identical input.
    ///
    /// Returns the child's collapsed terminal output enriched with
    /// `__reflective_retry_attempts__` on success, or an error envelope on
    /// exhaustion.
    #[tracing::instrument(
        level = "info",
        name = "reflective_retry",
        skip_all,
        fields(
            child_workflow_id = %child_wf_id,
            reflection_workflow_id = %reflection_wf_id,
            max_retries,
        ),
    )]
    pub async fn dispatch_reflective_retry(
        &self,
        initial_input: JsonValue,
        child_wf_id: Uuid,
        reflection_wf_id: Uuid,
        max_retries: u32,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
    ) -> JsonValue {
        let mut current_input = initial_input;
        let mut last_error = String::new();

        for attempt in 1..=max_retries {
            let clean_input = if let Some(obj) = current_input.as_object() {
                let mut c = obj.clone();
                c.retain(|k, _| !k.starts_with("__"));
                serde_json::Value::Object(c)
            } else {
                current_input.clone()
            };

            let child_out = match self
                .execute_subworkflow_graph(
                    child_wf_id,
                    clean_input.clone(),
                    dispatcher.clone(),
                    worker_shared_key.clone(),
                )
                .await
            {
                Ok(v) => v,
                Err(e) => e.into_error_envelope("ReflectiveRetry child"),
            };

            if !child_out
                .get("__error")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                Self::emit_quality_gate_event("reflective_retry", true, None, Some(attempt), None);
                let mut out = if let Some(obj) = child_out.as_object() {
                    obj.clone()
                } else {
                    let mut m = serde_json::Map::new();
                    m.insert("output".to_string(), child_out.clone());
                    m
                };
                out.insert(
                    "__reflective_retry_attempts__".to_string(),
                    serde_json::json!(attempt),
                );
                return serde_json::Value::Object(out);
            }

            last_error = child_out
                .get("error_message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error")
                .to_string();

            if attempt < max_retries {
                let reflect_input = serde_json::json!({
                    "input": clean_input,
                    "error": last_error,
                    "attempt": attempt,
                });
                if let Ok(reflection_out) = self
                    .execute_subworkflow_graph(
                        reflection_wf_id,
                        reflect_input,
                        dispatcher.clone(),
                        worker_shared_key.clone(),
                    )
                    .await
                {
                    let mut merged = if let Some(obj) = current_input.as_object() {
                        obj.clone()
                    } else {
                        serde_json::Map::new()
                    };
                    if let Some(obj) = reflection_out.as_object() {
                        for (k, v) in obj {
                            if !k.starts_with("__") {
                                merged.insert(k.clone(), v.clone());
                            }
                        }
                    }
                    current_input = serde_json::Value::Object(merged);
                }
            }
        }

        Self::emit_quality_gate_event(
            "reflective_retry",
            false,
            None,
            Some(max_retries),
            Some("exhausted"),
        );
        serde_json::json!({
            "__error": true,
            "error_message": format!(
                "Reflective retry exhausted {} attempts. Last error: {}",
                max_retries, last_error
            ),
        })
    }

    /// One-shot dispatch of a `SubWorkflow` system node.
    ///
    /// Strips engine metadata (`__*`) from the inbound parent inputs before
    /// passing as the sub-workflow trigger, then returns the collapsed
    /// terminal output (single-terminal workflows flatten to their leaf
    /// output; multi-terminal fall back to label-keyed map).
    pub async fn dispatch_subworkflow(
        &self,
        inputs: JsonValue,
        sub_wf_id: Uuid,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
    ) -> JsonValue {
        // Strip internal metadata keys so sub-workflow input doesn't carry
        // engine internals (`__trigger_input__`, `__fuel_consumed__`, …).
        let clean_input = if let Some(obj) = inputs.as_object() {
            let mut cleaned = obj.clone();
            cleaned.retain(|k, _| !k.starts_with("__"));
            serde_json::Value::Object(cleaned)
        } else {
            inputs
        };
        match self
            .execute_subworkflow_graph(sub_wf_id, clean_input, dispatcher, worker_shared_key)
            .await
        {
            Ok(collapsed) => collapsed,
            Err(e) => {
                tracing::error!(sub_workflow_id = %sub_wf_id, error = ?e, "Sub-workflow execution failed");
                e.into_error_envelope("Sub-workflow")
            }
        }
    }

    /// Emit a `target: "talos_workflow_engine"` event for a quality-gate outcome.
    ///
    /// Structured telemetry for judge / reflective-retry / ensemble so operators
    /// can answer "what's our judge pass rate?" and "how often does reflection
    /// rescue a failing child?" without plumbing custom metrics per-workflow.
    fn emit_quality_gate_event(
        kind: &'static str,
        passed: bool,
        score: Option<f64>,
        attempts: Option<u32>,
        extra: Option<&str>,
    ) {
        tracing::info!(
            target: "talos_workflow_engine",
            event_kind = "quality_gate",
            gate = kind,
            passed = passed,
            score = score,
            attempts = attempts,
            extra = extra,
            "quality gate completed"
        );
    }

    /// One-shot dispatch of a Judge system node. Builds the judge input from
    /// `parent_inputs`, runs the judge sub-workflow, parses the verdict, and
    /// returns the final output envelope that the outer loop will insert into
    /// the results map.
    ///
    /// # When to call this directly
    ///
    /// Most consumers don't — putting a [`SystemNodeKind::Judge`] node
    /// in the workflow graph and letting the scheduler call this method
    /// is the supported path. This method is also `pub` so embedders
    /// who want a one-off judge invocation outside any graph (e.g. an
    /// MCP handler that scores a single LLM output, a CLI tool, an
    /// HTTP endpoint that takes content + rubric and returns a
    /// verdict) can call it directly without authoring a wrapper
    /// graph. Same `JudgeVerdict` shape, same sub-workflow lookup
    /// path, same envelope. See
    /// [`docs/sub-workflow-composition.md`](https://github.com/aegix-dev/talos-workflow-engine/blob/main/docs/sub-workflow-composition.md)
    /// for the verdict-shape contract.
    ///
    /// Shared by the `run` and `run_with_seed` dispatch loops — both previously
    /// inlined ~100 lines of near-identical logic here.
    //
    // `skip_all` is load-bearing: `parent_inputs` may carry plaintext
    // post-template-interpolation secrets; never forward it to a tracing
    // sink. Identifying fields are explicit so production debugging can
    // correlate without UUID hand-tracing.
    #[tracing::instrument(
        level = "info",
        name = "judge",
        skip_all,
        fields(
            judge_workflow_id = %judge_wf_id,
            pass_threshold = ?pass_threshold,
        ),
    )]
    pub async fn dispatch_judge(
        &self,
        parent_inputs: JsonValue,
        judge_wf_id: Uuid,
        rubric: String,
        pass_threshold: Option<f64>,
        on_failure: &str,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
    ) -> JsonValue {
        let judge_input = serde_json::json!({
            "content": &parent_inputs,
            "rubric": rubric,
        });
        match self
            .execute_subworkflow_graph(judge_wf_id, judge_input, dispatcher, worker_shared_key)
            .await
        {
            Ok(collapsed) => {
                let verdict = JudgeVerdict::from_collapsed(&collapsed);
                let JudgeVerdict {
                    score,
                    passed: passed_raw,
                    reasoning,
                    feedback,
                    malformed_field_count,
                } = verdict;
                let passed = if let Some(threshold) = pass_threshold {
                    passed_raw && score >= threshold
                } else {
                    passed_raw
                };
                Self::emit_quality_gate_event(
                    "judge",
                    passed,
                    Some(score),
                    None,
                    if malformed_field_count > 0 {
                        Some("malformed_verdict")
                    } else {
                        None
                    },
                );
                if passed {
                    let mut out = if let Some(obj) = parent_inputs.as_object() {
                        obj.clone()
                    } else {
                        serde_json::Map::new()
                    };
                    out.insert("__judge_score__".to_string(), serde_json::json!(score));
                    out.insert("__judge_passed__".to_string(), serde_json::json!(true));
                    out.insert(
                        "__judge_reasoning__".to_string(),
                        serde_json::json!(reasoning),
                    );
                    out.insert(
                        "__judge_feedback__".to_string(),
                        serde_json::json!(feedback),
                    );
                    serde_json::Value::Object(out)
                } else if on_failure == "passthrough" {
                    // Forward the parent output enriched with the rejection
                    // envelope. Downstream edges can conditional-route on
                    // `__judge_passed__ == false` without tripping the error
                    // path — same semantics as `verify` with
                    // `on_failure: passthrough`.
                    let mut out = if let Some(obj) = parent_inputs.as_object() {
                        obj.clone()
                    } else {
                        serde_json::Map::new()
                    };
                    out.insert("__judge_score__".to_string(), serde_json::json!(score));
                    out.insert("__judge_passed__".to_string(), serde_json::json!(false));
                    out.insert("__judge_rejected__".to_string(), serde_json::json!(true));
                    out.insert(
                        "__judge_reasoning__".to_string(),
                        serde_json::json!(reasoning),
                    );
                    out.insert(
                        "__judge_feedback__".to_string(),
                        serde_json::json!(feedback),
                    );
                    serde_json::Value::Object(out)
                } else {
                    serde_json::json!({
                        "__error": true,
                        "error_message": format!("Judge rejected output: {} (score: {:.2})", reasoning, score),
                        "__judge_score__": score,
                        "__judge_passed__": false,
                        "__judge_feedback__": feedback,
                    })
                }
            }
            Err(e) => e.into_error_envelope("Judge"),
        }
    }

    /// Inline-expression judge — evaluate `verdict_expr` against the
    /// gathered parent inputs via the configured
    /// [`ExpressionEvaluator`](talos_workflow_engine_core::ExpressionEvaluator),
    /// parse the result as a [`JudgeVerdict`], and produce the same
    /// pass / reject envelope shape as the sub-workflow
    /// [`dispatch_judge`](Self::dispatch_judge) path.
    ///
    /// Synchronous because it does no I/O — purely an expression
    /// evaluation. Useful when the verdict reduces to a one-line
    /// scoring function and the cost of authoring + dispatching a
    /// separate sub-workflow isn't justified. Promote to a full
    /// `Judge` once the rubric grows its own model call or branching.
    ///
    /// On evaluator failure (no evaluator wired, expression error,
    /// non-object output) the function emits an error envelope rather
    /// than panicking — the engine already treats `__error: true` as
    /// a node-level failure routable through `ErrorHandler` edges.
    ///
    /// # When to call this directly
    ///
    /// Same shape as
    /// [`dispatch_judge`](Self::dispatch_judge): the supported path
    /// is to author a [`SystemNodeKind::InlineJudge`] in the graph
    /// and let the scheduler dispatch it. Embedders who want to
    /// score a single value outside any graph (e.g. a CLI checking
    /// quality of a one-off LLM output, an HTTP handler that scores
    /// content + verdict-expr and returns a verdict) can call this
    /// method directly. Synchronous — no `await` required at the
    /// call site.
    //
    // `skip_all` keeps `parent_inputs` and the expression text out of
    // the span — both can carry plaintext secrets after caller-side
    // template interpolation.
    #[cfg(feature = "llm-primitives")]
    #[tracing::instrument(
        level = "info",
        name = "inline_judge",
        skip_all,
        fields(pass_threshold = ?pass_threshold),
    )]
    pub fn dispatch_inline_judge(
        &self,
        parent_inputs: JsonValue,
        verdict_expr: &str,
        pass_threshold: Option<f64>,
        on_failure: &str,
    ) -> JsonValue {
        let raw_verdict = match self.eval_json(verdict_expr, &parent_inputs) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "InlineJudge: verdict expression failed to evaluate",
                );
                return serde_json::json!({
                    "__error": true,
                    "error_message": format!("InlineJudge expression failed: {e}"),
                });
            }
        };
        let verdict = JudgeVerdict::from_collapsed(&raw_verdict);
        let JudgeVerdict {
            score,
            passed: passed_raw,
            reasoning,
            feedback,
            malformed_field_count,
        } = verdict;
        let passed = if let Some(threshold) = pass_threshold {
            passed_raw && score >= threshold
        } else {
            passed_raw
        };
        Self::emit_quality_gate_event(
            "inline_judge",
            passed,
            Some(score),
            None,
            if malformed_field_count > 0 {
                Some("malformed_verdict")
            } else {
                None
            },
        );
        if passed {
            let mut out = if let Some(obj) = parent_inputs.as_object() {
                obj.clone()
            } else {
                serde_json::Map::new()
            };
            out.insert("__judge_score__".to_string(), serde_json::json!(score));
            out.insert("__judge_passed__".to_string(), serde_json::json!(true));
            out.insert(
                "__judge_reasoning__".to_string(),
                serde_json::json!(reasoning),
            );
            out.insert(
                "__judge_feedback__".to_string(),
                serde_json::json!(feedback),
            );
            serde_json::Value::Object(out)
        } else if on_failure == "passthrough" {
            let mut out = if let Some(obj) = parent_inputs.as_object() {
                obj.clone()
            } else {
                serde_json::Map::new()
            };
            out.insert("__judge_score__".to_string(), serde_json::json!(score));
            out.insert("__judge_passed__".to_string(), serde_json::json!(false));
            out.insert("__judge_rejected__".to_string(), serde_json::json!(true));
            out.insert(
                "__judge_reasoning__".to_string(),
                serde_json::json!(reasoning),
            );
            out.insert(
                "__judge_feedback__".to_string(),
                serde_json::json!(feedback),
            );
            serde_json::Value::Object(out)
        } else {
            serde_json::json!({
                "__error": true,
                "error_message": format!(
                    "InlineJudge rejected output: {} (score: {:.2})",
                    reasoning, score
                ),
                "__judge_score__": score,
                "__judge_passed__": false,
                "__judge_feedback__": feedback,
            })
        }
    }

    /// Execute a sub-workflow by ID with the given trigger input, and return
    /// the collapsed terminal output.
    ///
    /// This is the canonical sub-workflow invocation path. It encapsulates what
    /// was previously duplicated at ~10 call sites (judge, ensemble, reflective-
    /// retry, sub_workflow, llm-dispatch) across two dispatch loops:
    ///
    /// 1. Load the sub-workflow graph from the DB (via the registry's db_pool).
    /// 2. Build an engine, register a synthetic `__trigger__` node, wire it to
    ///    every root so root nodes execute instead of being pre-seeded.
    /// 3. `run_with_seed` with `trigger_input` as the trigger's output.
    /// 4. Call [`Self::collapse_subworkflow_output`] to flatten the
    ///    results into the shape callers expect (single-terminal → its
    ///    unwrapped output).
    ///
    /// Returns `Ok(JsonValue)` with the collapsed output, or [`SubflowError`]
    /// which each caller converts into their own error envelope via
    /// [`SubflowError::into_error_envelope`].
    #[tracing::instrument(
        level = "info",
        name = "subworkflow",
        skip_all,
        fields(sub_workflow_id = %sub_wf_id),
    )]
    pub async fn execute_subworkflow_graph(
        &self,
        sub_wf_id: Uuid,
        trigger_input: JsonValue,
        dispatcher: Arc<dyn talos_workflow_engine_core::NodeDispatcher>,
        worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
    ) -> Result<JsonValue, SubflowError> {
        self.module_fetcher
            .as_ref()
            .ok_or(SubflowError::NoRegistry)?;
        let user_id = self.user_id.ok_or(SubflowError::NoUserId)?;
        self.secrets_resolver
            .as_ref()
            .ok_or(SubflowError::NoSecretsResolver)?;

        let graph_json = self
            .get_sub_workflow_graph(sub_wf_id, user_id)
            .await
            .ok_or_else(|| SubflowError::GraphNotFound(sub_wf_id))?;

        // Reuse the parent's adapter Arcs (Arc::clone is a refcount
        // bump per trait object — cheap). Use the *guarded* path
        // (`into_engine_with_graph`) so the recursion-depth check
        // fires here — without it, a self-referential workflow
        // would stack-overflow the reactor instead of returning a
        // typed error.
        let mut sub_engine = self
            .adapter_set()
            .into_engine_with_graph(&graph_json)
            .map_err(|e| SubflowError::BuildFailed(e.to_string()))?;

        // Cross-actor isolation: when a parent dispatches a sub-workflow
        // bound to a *different* actor, hydrate the sub-engine with that
        // actor's `__actor_context__` so downstream LLM nodes with
        // INJECT_CONTEXT=true see the sub-workflow's intended persona,
        // not nothing. Without this hook, the freshly-built sub-engine
        // has `actor_context = None` regardless of the sub-workflow's
        // bound actor — which silently degrades cross-actor patterns
        // (e.g. CEO calls VPE) to "second LLM call with the same parent
        // context" instead of real cross-actor consultation. Returning
        // `None` from the resolver keeps the pre-hook behaviour exactly.
        if let Some(resolver) = self.sub_actor_context_resolver.as_ref() {
            if let Some(ctx) = resolver.resolve(sub_wf_id, user_id).await {
                sub_engine.set_actor_context(ctx);
            }
        }

        // Synthetic trigger node: seeded with the caller's input,
        // wired to every root so root-level modules actually execute.
        // Delegates to the shared helper so this path and the public
        // `run_with_trigger_input_transport` can't drift.
        let trigger_node_id = sub_engine.ensure_trigger_node_wired_to_roots();
        let mut initial_results = HashMap::new();
        initial_results.insert(trigger_node_id, trigger_input);

        let ctx = sub_engine
            .run_with_seed_with_transport(
                dispatcher,
                worker_shared_key,
                initial_results,
                Uuid::new_v4(),
            )
            .await
            .map_err(|e| SubflowError::ExecutionFailed(e.to_string()))?;

        Ok(Self::collapse_subworkflow_output(&ctx.results, &sub_engine))
    }

    /// Reduce a sub-workflow's `results` map into the single value
    /// the parent dispatch site sees as "the sub-workflow's output."
    ///
    /// Two cases:
    ///
    /// * **One terminal node.** Returns that node's output unwrapped.
    ///   This is the canonical case — `Judge`, `Ensemble`, and
    ///   `ReflectiveRetry` all rely on it for their structured-shape
    ///   parsing.
    /// * **Multiple terminal nodes (or a complex shape).** Falls back
    ///   to a label-keyed map so the parent retains every terminal's
    ///   output by its node label.
    ///
    /// Skipped nodes (`{"__skipped": true}`) and the synthetic
    /// `__trigger__` node added by sub-workflow dispatch are filtered
    /// out before collapse.
    pub fn collapse_subworkflow_output(
        ctx_results: &HashMap<Uuid, JsonValue>,
        sub_engine: &ParallelWorkflowEngine,
    ) -> JsonValue {
        // Index uuid -> NodeIndex once (O(V)) so per-node lookups stay O(1).
        let mut uuid_to_idx: HashMap<Uuid, NodeIndex> =
            HashMap::with_capacity(sub_engine.graph.node_count());
        for idx in sub_engine.graph.node_indices() {
            uuid_to_idx.insert(sub_engine.graph[idx], idx);
        }

        // Partition node outputs into (terminal, non_terminal) while stripping
        // skipped + trigger + engine envelope.
        let mut terminals: Vec<(String, JsonValue)> = Vec::new();
        let mut non_terminals: Vec<(String, JsonValue)> = Vec::new();
        for (nid, output) in ctx_results {
            if output
                .get("__skipped")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                continue;
            }
            let label = sub_engine
                .node_labels
                .get(nid)
                .cloned()
                .unwrap_or_else(|| nid.to_string());
            if label == "__trigger__" {
                continue;
            }
            let unwrapped = Self::unwrap_output(output).clone();
            let is_terminal = match uuid_to_idx.get(nid) {
                Some(idx) => {
                    sub_engine
                        .graph
                        .neighbors_directed(*idx, Direction::Outgoing)
                        .count()
                        == 0
                }
                // Node present in results but not in the graph — treat as non-terminal
                // so it can't accidentally shadow the real leaf.
                None => false,
            };
            if is_terminal {
                terminals.push((label, unwrapped));
            } else {
                non_terminals.push((label, unwrapped));
            }
        }

        // Canonical path: exactly one terminal → its output IS the sub-workflow output.
        if terminals.len() == 1 {
            return terminals.into_iter().next().unwrap().1;
        }

        // Fallback: label-keyed map. Insert non-terminals first, then terminals,
        // so a terminal's label wins any collision (stable, predictable ordering).
        let mut map = serde_json::Map::with_capacity(non_terminals.len() + terminals.len());
        for (label, output) in non_terminals {
            map.insert(label, output);
        }
        for (label, output) in terminals {
            map.insert(label, output);
        }
        JsonValue::Object(map)
    }

    /// Resolve the workflow's original trigger input from the completed-
    /// results map. Returns `None` when the synthetic `__trigger__` node
    /// hasn't emitted yet (should never happen on the main dispatch
    /// path, but the reactor may call this before seed hydration under
    /// some edge cases).
    ///
    /// Behaviour for nested cases:
    ///
    /// * When the parent workflow was itself invoked as a sub-workflow,
    ///   its `results[__trigger__]` is a wrapper blob shaped like
    ///   `{..upstream, "__trigger_input__": <root-user-trigger>}`. We
    ///   unwrap one level so callers downstream see the **original
    ///   user-facing trigger** — which is the whole point of the
    ///   `__trigger_input__` key (survive sub-workflow boundaries).
    /// * When no wrapper is present (top-level workflow), the trigger
    ///   blob IS the trigger input — returned as-is.
    ///
    /// This keeps the scaffold's "`__trigger_input__` is always preserved"
    /// contract honest even for 2+ level deep composition. Single source
    /// of truth — all three callers (loop body dispatcher, single-node
    /// dispatcher, sub-workflow dispatcher) use this helper.
    pub(crate) fn extract_trigger_input(
        &self,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<JsonValue> {
        let trigger_blob = self
            .node_labels
            .iter()
            .find(|(_, label)| label.as_str() == "__trigger__")
            .and_then(|(uuid, _)| results.get(uuid))
            .cloned()?;
        // Nested case: we're a sub-workflow whose trigger carries the
        // outer user trigger under `__trigger_input__`. Unwrap one level.
        if let Some(obj) = trigger_blob.as_object() {
            if let Some(inner) = obj.get("__trigger_input__") {
                return Some(inner.clone());
            }
        }
        Some(trigger_blob)
    }

    /// Strip the engine's wrapping envelope from a node output if
    /// present. Workers sometimes return `{"input": <real>, "score":
    /// ..., "passed": ...}` where the real payload is under `"input"`
    /// and the outer keys are duplicated for convenience; this helper
    /// returns a reference to the unwrapped inner value when that
    /// wrapper is detected, otherwise to `output` unchanged.
    pub fn unwrap_output(output: &JsonValue) -> &JsonValue {
        // If output is a JSON string that contains JSON, try to parse it
        if let JsonValue::String(_s) = output {
            // String output from WASM — try to parse as JSON
            // (handled at a higher level, just return as-is here)
            return output;
        }
        // If output looks like the engine wrapper, strip it down to clean payload.
        if let Some(obj) = output.as_object() {
            // Case 1: {"config": {...}, "input": {...}, ...fields} — extract input
            if obj.contains_key("input") {
                if let Some(inner) = obj.get("input") {
                    if let Some(inner_obj) = inner.as_object() {
                        let is_wrapper = inner_obj.keys().all(|k| obj.contains_key(k));
                        if is_wrapper && !inner_obj.is_empty() {
                            return inner;
                        }
                    }
                }
            }
            // Case 2: {"config": {...}, "input": null} — extract config (direct tool with no input)
            if obj.contains_key("config") && obj.get("input").map(|v| v.is_null()).unwrap_or(false)
            {
                if let Some(config) = obj.get("config") {
                    if config.is_object()
                        && !config.as_object().map(|m| m.is_empty()).unwrap_or(true)
                    {
                        return config;
                    }
                }
                // config is also empty — return empty object
                if obj.len() == 2 {
                    return &JsonValue::Null;
                }
            }
        }
        output
    }

    /// Gather inputs for a node based on completed parent results.
    ///
    /// - **Single parent**: passes the parent output directly (unwrapped)
    /// - **Multiple parents**: wraps outputs in an object keyed by user-defined
    ///   node label (from `node_labels`) or falling back to the internal UUID.
    pub(crate) fn gather_inputs(
        &self,
        node_idx: NodeIndex,
        results: &HashMap<Uuid, JsonValue>,
    ) -> JsonValue {
        let parents: Vec<(Uuid, &JsonValue)> = self
            .graph
            .neighbors_directed(node_idx, Direction::Incoming)
            .filter_map(|p_idx| {
                let pid = self.graph[p_idx];
                results.get(&pid).map(|out| (pid, Self::unwrap_output(out)))
            })
            .collect();

        match parents.len() {
            0 => JsonValue::Object(Map::new()),
            1 => {
                // Single parent: pass output directly — no UUID wrapping.
                parents[0].1.clone()
            }
            _ => {
                // Multiple parents: key by user-defined label or internal UUID.
                let mut map = Map::new();
                for (pid, output) in parents {
                    let key = self
                        .node_labels
                        .get(&pid)
                        .cloned()
                        .unwrap_or_else(|| pid.to_string());
                    map.insert(key, output.clone());
                }
                JsonValue::Object(map)
            }
        }
    }

    /// Load the Wasm bytecode for a given node ID (enforces user ownership).
    ///
    /// Three layers: the engine-local speculative-prefetch cache, a
    /// "no fetcher configured" MVP fallback for dev harnesses, and — in
    /// the normal case — a delegation to the configured
    /// [`ModuleFetcher`] which owns the real resolution pipeline
    /// (primary lookup, stale-ref-by-name, template fallback,
    /// precompiled-template fallback, Redis cache warm-up).
    pub(crate) async fn fetch_module(
        &self,
        node_id: Uuid,
    ) -> Result<talos_workflow_engine_core::WasmModuleArtifact, String> {
        if let Some(cached) = self.module_prefetch_cache.remove(&node_id) {
            tracing::debug!(node_id = %node_id, "fetch_module: speculative prefetch cache hit");
            return Ok(cached.1);
        }
        let Some(fetcher) = self.module_fetcher.as_ref() else {
            // Dev / smoke-test convenience: a bare `ParallelWorkflowEngine::new()`
            // with no services wired up falls through to a local wasm artifact.
            // Gated on `debug_assertions` so release binaries never read arbitrary
            // files off disk when a caller misconfigures — they get a clear error
            // instead.
            #[cfg(debug_assertions)]
            {
                let bytes =
                    std::fs::read("example-node/target/wasm32-wasi/release/my_first_node.wasm")
                        .map_err(|e| format!("failed to read wasm module: {}", e))?;
                return Ok(talos_workflow_engine_core::WasmModuleArtifact {
                    module_id: self.resolve_module_id(node_id),
                    content_hash: "example".to_string(),
                    wasm_bytes: bytes,
                    oci_url: None,
                    max_fuel: 1_000_000,
                    capability_world: "unknown".to_string(),
                    allowed_hosts: vec![],
                    allowed_methods: vec![],
                    allowed_secrets: vec![],
                    requires_approval_for: vec![],
                    integration_name: None,
                    config: None,
                });
            }
            #[cfg(not(debug_assertions))]
            return Err(
                "engine has no module fetcher configured; construct with `with_services` \
                 or call `set_module_fetcher` before dispatching"
                    .to_string(),
            );
        };
        let user_id = self.user_id.ok_or_else(|| {
            "Module execution requires user context (user_id not set)".to_string()
        })?;
        let module_id = self.resolve_module_id(node_id);
        fetcher
            .fetch(module_id, user_id)
            .await
            .map_err(|e| e.to_string())
    }

    // ── Shared node-type helpers ──────────────────────────────────────────
    // The following methods extract duplicated per-node-type logic that was
    // previously inlined in both `run()` and `run_with_seed()`.  Each helper
    // performs the pure computation for a local-dispatch node kind and returns
    // the output `JsonValue` to be inserted into the results map.  The caller
    // is responsible for inserting the result, emitting lifecycle events, and
    // unblocking successors.

    /// Aggregate parent outputs for a `FanIn` node.
    ///
    /// Collects all incoming node outputs and combines them according to
    /// `join_mode`.  If `aggregation_expr` is provided, it is evaluated as a
    /// Rhai condition against the aggregated value — on failure the result is
    /// replaced with `{"__aggregation_failed": true}`.
    pub(crate) fn aggregate_fan_in(
        &self,
        node_idx: NodeIndex,
        results: &HashMap<Uuid, JsonValue>,
        join_mode: &JoinMode,
        aggregation_expr: &Option<String>,
    ) -> JsonValue {
        let node_id = self.graph[node_idx];
        let parent_outputs: Vec<&JsonValue> = self
            .graph
            .neighbors_directed(node_idx, Direction::Incoming)
            .filter_map(|p| results.get(&self.graph[p]))
            .collect();

        let aggregated = match join_mode {
            JoinMode::All => serde_json::json!(parent_outputs),
            JoinMode::Any => parent_outputs
                .first()
                .map(|v| (*v).clone())
                .unwrap_or(serde_json::json!(null)),
            JoinMode::Majority => serde_json::json!(parent_outputs),
            JoinMode::N(_) => serde_json::json!(parent_outputs),
            // `JoinMode` is `#[non_exhaustive]`; default unknown future
            // variants to the conservative `All`-shaped aggregation.
            _ => serde_json::json!(parent_outputs),
        };

        let final_result = if let Some(expr) = aggregation_expr {
            if self.eval_bool(expr, &aggregated) {
                aggregated
            } else {
                serde_json::json!({"__aggregation_failed": true})
            }
        } else {
            aggregated
        };

        tracing::info!(
            node_id = %node_id,
            join_mode = ?join_mode,
            parent_count = parent_outputs.len(),
            "FanIn aggregation completed locally"
        );

        final_result
    }

    /// Gather and collect parent outputs for a Collect node.
    ///
    /// Strips engine-internal metadata (`__`-prefixed keys) from each branch
    /// output — EXCEPT error markers (`__error`, `__continued`), which are
    /// preserved so downstream handlers have a reliable signal when a
    /// `continue_on_error` parent errored. `error_message` is already a
    /// non-prefixed field and passes through unconditionally.
    pub(crate) fn collect_parent_outputs_for_node(
        &self,
        node_idx: NodeIndex,
        results: &HashMap<Uuid, JsonValue>,
    ) -> JsonValue {
        let node_id = self.graph[node_idx];
        let parent_outputs: Vec<JsonValue> = self
            .graph
            .neighbors_directed(node_idx, Direction::Incoming)
            .filter_map(|p| results.get(&self.graph[p]).cloned())
            .map(|v| {
                if let JsonValue::Object(mut obj) = v {
                    obj.retain(|k, _| !k.starts_with("__") || k == "__error" || k == "__continued");
                    JsonValue::Object(obj)
                } else {
                    v
                }
            })
            .collect();

        let parent_count = parent_outputs.len();
        let collected = serde_json::json!({
            "items": parent_outputs,
            "count": parent_count,
        });

        tracing::info!(
            node_id = %node_id,
            parent_count,
            "Collect node gathered all parent outputs into object"
        );

        collected
    }

    /// Build accumulated context from all completed node results so far.
    ///
    /// Returns a JSON object keyed by node label containing each prior node's
    /// output, with engine-internal `__`-prefixed keys stripped from values.
    /// Nodes whose labels start with `__` (engine internals like `__trigger__`)
    /// are omitted entirely. Returns `None` if no user-visible results exist.
    fn build_accumulated_context(
        node_labels: &HashMap<Uuid, String>,
        results: &HashMap<Uuid, JsonValue>,
    ) -> Option<serde_json::Value> {
        let accumulated: Map<String, JsonValue> = results
            .iter()
            .filter_map(|(id, val)| {
                let label = node_labels
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| id.to_string());
                // Skip engine-internal nodes (trigger, etc.)
                if label.starts_with("__") {
                    return None;
                }
                // Strip __-prefixed metadata keys from the value
                let cleaned = if let JsonValue::Object(obj) = val {
                    let mut c = obj.clone();
                    c.retain(|k, _| !k.starts_with("__"));
                    JsonValue::Object(c)
                } else {
                    val.clone()
                };
                Some((label, cleaned))
            })
            .collect();

        if accumulated.is_empty() {
            None
        } else {
            Some(JsonValue::Object(accumulated))
        }
    }

    /// Compute the Synthesize node output.
    ///
    /// Collects parent outputs (stripping `__`-prefixed metadata EXCEPT error
    /// markers `__error` / `__continued`, so downstream synthesis can detect
    /// errored branches), optionally evaluates a Rhai `synthesis_expr`, and
    /// returns the synthesized value. Array size is capped at 500 to match
    /// Rhai limits.
    pub(crate) fn synthesize_parent_outputs(
        &self,
        node_idx: NodeIndex,
        results: &HashMap<Uuid, JsonValue>,
        synthesis_expr: &Option<String>,
    ) -> JsonValue {
        let node_id = self.graph[node_idx];
        let parent_outputs: Vec<JsonValue> = self
            .graph
            .neighbors_directed(node_idx, Direction::Incoming)
            .filter_map(|p| results.get(&self.graph[p]).cloned())
            .map(|v| {
                if let JsonValue::Object(mut obj) = v {
                    obj.retain(|k, _| !k.starts_with("__") || k == "__error" || k == "__continued");
                    JsonValue::Object(obj)
                } else {
                    v
                }
            })
            .collect();

        let parent_count = parent_outputs.len();

        if parent_count > 500 {
            tracing::warn!(
                node_id = %node_id,
                parent_count,
                "Synthesize: parent_outputs exceeds 500 items — truncating to 500"
            );
        }
        let parent_outputs: Vec<JsonValue> = parent_outputs.into_iter().take(500).collect();
        let parent_count = parent_outputs.len();

        let synthesized = if let Some(ref expr) = synthesis_expr {
            let items_json = serde_json::json!({
                "items": &parent_outputs,
                "count": parent_count,
            });
            match self.eval_json(expr, &items_json) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        node_id = %node_id,
                        error = %e,
                        "Synthesize Rhai expression failed — falling back to raw collect"
                    );
                    serde_json::json!({ "items": &parent_outputs, "count": parent_count })
                }
            }
        } else {
            serde_json::json!({ "items": &parent_outputs, "count": parent_count })
        };

        tracing::info!(
            node_id = %node_id,
            parent_count,
            has_expr = synthesis_expr.is_some(),
            "Synthesize node processed parent outputs"
        );

        synthesized
    }

    /// Evaluate a Verify node against its parent output.
    ///
    /// Returns `(result_json, passed)` where `passed` indicates whether the
    /// verification condition was satisfied.  The caller uses `passed` to
    /// select the event status string ("Completed" vs "Failed").
    pub(crate) fn evaluate_verify_node(
        &self,
        node_idx: NodeIndex,
        results: &HashMap<Uuid, JsonValue>,
        condition: &str,
        check_label: &str,
        on_failure: &str,
    ) -> (JsonValue, bool) {
        let node_id = self.graph[node_idx];
        let parent_output = self.gather_inputs(node_idx, results);
        let passed = self.eval_bool(condition, &parent_output);

        let verify_result = if passed {
            let mut out = parent_output;
            if let Some(obj) = out.as_object_mut() {
                obj.insert("__verified__".to_string(), serde_json::json!(true));
                obj.insert(
                    "__check_label__".to_string(),
                    serde_json::Value::String(check_label.to_string()),
                );
            }
            out
        } else if on_failure == "passthrough" {
            let mut out = parent_output;
            if let Some(obj) = out.as_object_mut() {
                obj.insert("__verified__".to_string(), serde_json::json!(false));
                obj.insert(
                    "__verification_failed__".to_string(),
                    serde_json::json!(true),
                );
                obj.insert(
                    "__check_label__".to_string(),
                    serde_json::Value::String(check_label.to_string()),
                );
                obj.insert(
                    "__verification_condition__".to_string(),
                    serde_json::Value::String(condition.to_string()),
                );
            }
            out
        } else {
            serde_json::json!({
                "__error": true,
                "error_message": format!(
                    "Verification failed for '{}': condition '{}' evaluated to false. \
                     Wire an error edge from this verify node to a fix-up workflow, or \
                     set on_failure: 'passthrough' to route conditionally downstream.",
                    check_label, condition
                ),
                "__verified__": false,
                "__check_label__": check_label,
            })
        };

        tracing::info!(
            node_id = %node_id,
            check_label = %check_label,
            passed,
            on_failure = %on_failure,
            "Verify node evaluated"
        );

        (verify_result, passed)
    }

    /// Evaluate a ConfidenceGate node against its parent output.
    ///
    /// Returns `Ok(result_json)` for pass/passthrough/error modes, or
    /// `Err(waiting_json)` when the gate is paused awaiting approval.
    /// The caller must handle the `Err` case by early-returning from the
    /// reactor loop with a `waiting: true` WorkflowContext.
    #[tracing::instrument(
        level = "info",
        name = "confidence_gate",
        skip_all,
        fields(
            execution_id = %execution_id,
            threshold,
            on_low_confidence,
        ),
    )]
    pub(crate) async fn evaluate_confidence_gate(
        &self,
        node_idx: NodeIndex,
        results: &HashMap<Uuid, JsonValue>,
        execution_id: Uuid,
        threshold: f64,
        confidence_path: &str,
        on_low_confidence: &str,
    ) -> Result<JsonValue, JsonValue> {
        let node_id = self.graph[node_idx];
        let parent_inputs = self.gather_inputs(node_idx, results);
        let confidence = parent_inputs
            .get(confidence_path)
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        if confidence >= threshold {
            let mut out = if let Some(obj) = parent_inputs.as_object() {
                obj.clone()
            } else {
                serde_json::Map::new()
            };
            out.insert(
                "__confidence_gate_passed__".to_string(),
                serde_json::json!(true),
            );
            out.insert(
                "__confidence_used__".to_string(),
                serde_json::json!(confidence),
            );
            return Ok(serde_json::Value::Object(out));
        }

        match on_low_confidence {
            "passthrough" => {
                let mut out = if let Some(obj) = parent_inputs.as_object() {
                    obj.clone()
                } else {
                    serde_json::Map::new()
                };
                out.insert(
                    "__confidence_gate_failed__".to_string(),
                    serde_json::json!(true),
                );
                out.insert(
                    "__confidence_used__".to_string(),
                    serde_json::json!(confidence),
                );
                Ok(serde_json::Value::Object(out))
            }
            "error" => Ok(serde_json::json!({
                "__error": true,
                "error_message": format!(
                    "Confidence gate: {:.3} < threshold {:.3}",
                    confidence, threshold
                ),
                "__confidence_used__": confidence,
            })),
            _ => {
                // "pause" — create approval request and suspend
                if let Some(ref gate) = self.approval_gate {
                    let required_for = vec!["low_confidence".to_string()];
                    match gate
                        .check_or_request(execution_id, node_id, &required_for, None)
                        .await
                    {
                        Ok(talos_workflow_engine_core::ApprovalStatus::Approved) => {
                            let mut out = if let Some(obj) = parent_inputs.as_object() {
                                obj.clone()
                            } else {
                                serde_json::Map::new()
                            };
                            out.insert(
                                "__confidence_gate_passed__".to_string(),
                                serde_json::json!(true),
                            );
                            out.insert(
                                "__confidence_used__".to_string(),
                                serde_json::json!(confidence),
                            );
                            out.insert(
                                "__confidence_gate_approved__".to_string(),
                                serde_json::json!(true),
                            );
                            Ok(serde_json::Value::Object(out))
                        }
                        Ok(talos_workflow_engine_core::ApprovalStatus::Pending) => {
                            Err(serde_json::json!({
                                "__waiting__": true,
                                "__confidence_used__": confidence,
                                "message": format!(
                                    "Confidence gate paused: {:.3} < threshold {:.3}. Awaiting approval.",
                                    confidence, threshold
                                ),
                            }))
                        }
                        Ok(talos_workflow_engine_core::ApprovalStatus::Denied { reason }) => {
                            Ok(serde_json::json!({
                                "__error": true,
                                "error_message": reason,
                            }))
                        }
                        // Fail-closed for non_exhaustive future variants.
                        Ok(_) => Ok(serde_json::json!({
                            "__error": true,
                            "error_message": "ConfidenceGate approval gate returned an unrecognized status",
                        })),
                        Err(e) => Ok(serde_json::json!({
                            "__error": true,
                            "error_message": format!("ConfidenceGate approval error: {}", e),
                        })),
                    }
                } else {
                    Ok(serde_json::json!({
                        "__error": true,
                        "error_message": "ConfidenceGate pause requires an approval gate",
                    }))
                }
            }
        }
    }

    /// Emit a `node_started` + `node_completed` pair through the engine's
    /// configured event sink. Fire-and-forget; no-op when no sink is
    /// configured.
    ///
    /// Both events are emitted from a **single** spawned task that
    /// awaits them sequentially, so `node_started` is guaranteed to
    /// commit before `node_completed`. This ordering matters for
    /// collapsed system nodes (Collect, Synthesize, Verify) whose
    /// downstream observers reconstruct per-node timelines from the
    /// events table.
    /// Owning user id for this execution, if any. See
    /// [`set_user_id`](Self::set_user_id) for the setter.
    #[must_use]
    pub(crate) fn user_id(&self) -> Option<Uuid> {
        self.user_id
    }

    /// `true` when a [`ModuleFetcher`] is wired in. Used by handlers
    /// that gate sub-workflow execution on registry availability.
    #[must_use]
    pub(crate) fn has_module_fetcher(&self) -> bool {
        self.module_fetcher.is_some()
    }

    /// Clone of the configured [`WorkflowGraphStore`] `Arc`, or `None`
    /// if the engine was built without one. Used by dispatch handlers
    /// that need to resolve target workflows by name or capability.
    #[must_use]
    pub(crate) fn graph_store_arc(&self) -> Option<Arc<dyn WorkflowGraphStore>> {
        self.graph_store.clone()
    }

    /// Actor id that owns this execution, if any. See
    /// [`set_actor_id`](Self::set_actor_id) for the setter.
    #[must_use]
    pub(crate) fn actor_id(&self) -> Option<Uuid> {
        self.actor_id
    }

    /// Per-node execution-timeout override set on the graph JSON, or
    /// `None` to use the scheduler's default. Exposed as a helper so
    /// the scheduler-handler module can read the value without
    /// touching the private map directly.
    #[must_use]
    pub(crate) fn node_timeout_for(&self, node_id: Uuid) -> Option<u64> {
        self.node_timeouts.get(&node_id).copied()
    }

    /// `FanIn` early-ready: apply a [`JoinMode::Any`] / `Majority` /
    /// `N(k)` short-circuit on `child` if it's a `FanIn` node and enough
    /// parents have completed to satisfy the join. Mutates `pending`
    /// by zeroing the child's counter when the join is satisfied.
    /// `JoinMode::All` waits for every parent and is the default
    /// zero-action branch.
    pub(crate) fn apply_fan_in_early_ready(
        &self,
        child: NodeIndex,
        pending: &mut HashMap<NodeIndex, usize>,
    ) {
        let Some((_, _, Some(SystemNodeKind::FanIn { join_mode, .. }))) =
            self.node_meta.get(&self.graph[child])
        else {
            return;
        };
        let total_parents = self
            .graph
            .neighbors_directed(child, Direction::Incoming)
            .count();
        let cnt = *pending.get(&child).unwrap_or(&0);
        let completed_parents = total_parents - cnt;
        match join_mode {
            JoinMode::Any => {
                if cnt > 0 {
                    pending.insert(child, 0);
                }
            }
            JoinMode::Majority => {
                if completed_parents > total_parents / 2 && cnt > 0 {
                    pending.insert(child, 0);
                }
            }
            JoinMode::N(n) => {
                if completed_parents >= *n as usize && cnt > 0 {
                    pending.insert(child, 0);
                }
            }
            JoinMode::All => {} // default: wait for everyone
            // `JoinMode` is `#[non_exhaustive]`; default to `All`-style
            // wait-for-everyone behavior for unknown variants until the
            // engine adds explicit handling.
            _ => {}
        }
    }

    /// Fire-and-forget emit of a `node_skipped` event. Used by the
    /// skip-condition pre-filter so the scheduler's standard dispatch
    /// branches don't each have to remember to log the skip.
    pub(crate) fn emit_node_skipped_event(&self, execution_id: Uuid, node_id: Uuid) {
        emit_event_spawn(
            &self.event_sink,
            NodeEventWrite {
                execution_id,
                event_type: "node_skipped".to_string(),
                node_id: Some(node_id),
                status: "Skipped".to_string(),
                log_message: None,
                iteration_index: None,
                error_class: None,
            },
        );
    }

    /// Fire-and-forget emit of a `loop_iteration` event. Used by the
    /// `Loop`-variant handler to log progress without blocking the
    /// dispatch loop on the event sink.
    pub(crate) fn emit_loop_iteration_event(
        &self,
        execution_id: Uuid,
        node_id: Uuid,
        iteration: u32,
        max_iters: u32,
    ) {
        emit_event_spawn(
            &self.event_sink,
            NodeEventWrite {
                execution_id,
                event_type: "loop_iteration".to_string(),
                node_id: Some(node_id),
                status: "Running".to_string(),
                log_message: Some(format!("Loop iteration {iteration}/{max_iters}")),
                iteration_index: Some(iteration as i32),
                error_class: None,
            },
        );
    }

    pub(crate) fn emit_node_lifecycle_events(
        &self,
        execution_id: Uuid,
        node_id: Uuid,
        status: &str,
        log_message: String,
    ) {
        let Some(sink) = self.event_sink.as_ref() else {
            return;
        };
        let sink = Arc::clone(sink);
        let status = status.to_string();
        tokio::spawn(async move {
            sink.emit(NodeEventWrite {
                execution_id,
                event_type: "node_started".to_string(),
                node_id: Some(node_id),
                status: "Running".to_string(),
                log_message: None,
                iteration_index: None,
                error_class: None,
            })
            .await;
            sink.emit(NodeEventWrite {
                execution_id,
                event_type: "node_completed".to_string(),
                node_id: Some(node_id),
                status,
                log_message: Some(log_message),
                iteration_index: None,
                error_class: None,
            })
            .await;
        });
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
    /// to abort them. If your transport supports mid-flight
    /// cancellation (e.g. NATS request-reply with a side subject),
    /// wire it through your `NodeDispatcher` impl using
    /// the
    /// [`DispatchJob`](talos_workflow_engine_core::DispatchJob)`::cancellation_token`
    /// field.
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
                    let accumulated_snapshot =
                        Self::build_accumulated_context(&self.node_labels, &results);
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
                    results.insert(node_id, output);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                // ── FanIn aggregation (local computation, no dispatch) ───────
                if let Some(output) = self.try_dispatch_fan_in(node_idx, node_id, &results) {
                    results.insert(node_id, output);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                // ── Collect dispatch (local computation) ─────────────────────
                if let Some(output) =
                    self.try_dispatch_collect(node_idx, node_id, execution_id, &results)
                {
                    results.insert(node_id, output);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                // ── Synthesize dispatch (collect + optional Rhai synthesis) ──
                if let Some(output) =
                    self.try_dispatch_synthesize(node_idx, node_id, execution_id, &results)
                {
                    results.insert(node_id, output);
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
                            results.insert(node_id, output);
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
                    results.insert(node_id, waiting_output);
                    return Ok(WorkflowContext {
                        results,
                        waiting: true,
                        ..Default::default()
                    });
                }

                // ── InlineJudge dispatch (sync expression-driven verdict) ────
                #[cfg(feature = "llm-primitives")]
                if let Some(output) = self.try_dispatch_inline_judge(node_idx, node_id, &results) {
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
                            results.insert(node_id, output);
                            self.unblock_successors(node_idx, &mut pending, &mut ready);
                            continue;
                        }
                        ConfidenceGateOutcome::Pause { waiting_output } => {
                            results.insert(node_id, waiting_output);
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
                    results.insert(node_id, output);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                // ── WhileLoop dispatch (local computation) ──────────────────
                if let Some(output) = self.try_dispatch_while_loop(node_idx, node_id, &results) {
                    results.insert(node_id, output);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                // ── RepeatLoop dispatch (local computation) ─────────────────
                if let Some(output) = self.try_dispatch_repeat_loop(node_idx, node_id, &results) {
                    results.insert(node_id, output);
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
                            results.insert(id, out);
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
                            results.insert(node_id, output);
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
                    results.insert(node_id, output);
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
                    results.insert(node_id, output);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                // ── ErrorHandler dispatch (pattern filtering) ───────────────
                if let Some(output) = self.try_dispatch_error_handler(node_idx, node_id, &results) {
                    results.insert(node_id, output);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                // ── Single-node dispatch ─────────────────────────────────────
                if let Some(error_envelope) = self.check_rate_limit(node_id).await {
                    results.insert(node_id, error_envelope);
                    self.unblock_successors(node_idx, &mut pending, &mut ready);
                    continue;
                }

                let inputs = self.gather_inputs(node_idx, &results);
                let accumulated_snapshot =
                    Self::build_accumulated_context(&self.node_labels, &results);
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
