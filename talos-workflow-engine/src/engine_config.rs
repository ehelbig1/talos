//! Engine configuration surface — extracted from engine.rs.
//!
//! Hosts the trivial getter/setter/builder methods on
//! [`ParallelWorkflowEngine`]: adapter wiring (`set_module_fetcher`,
//! `set_event_sink`, `set_checkpoint_store`, ...), execution knobs
//! (timeouts, fuel ceilings, output-size caps, subflow depth), and
//! identity/policy stamps (`set_actor_id`, `set_user_id`,
//! `set_max_llm_tier`, `set_egress_scope`, ...). Pure code movement
//! from the previous engine.rs location — no behaviour change. Lifted
//! out so the reactor file stays focused on scheduling while the
//! ~60-method config surface remains auditable in one place.

use std::collections::HashMap;
use std::sync::Arc;

use petgraph::graph::{DiGraph, NodeIndex};
use talos_workflow_engine_core::{
    CheckpointStore, EdgeLogic, EventSink, ModuleFetcher, NodeLifecycleHook, SecretsResolver,
    SystemNodeKind, WorkflowGraphStore,
};
use uuid::Uuid;

use crate::engine::{CheckpointConfig, ParallelWorkflowEngine};

impl ParallelWorkflowEngine {
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

    /// Install the adaptive-fuel (Phase 2) learned ceilings for this run, keyed
    /// by node label. The controller computes these from `execution_cost_rollup`
    /// history (p95/max × headroom, tenant-scoped) and injects them before
    /// running. Empty ⇒ adaptive off / no history ⇒ static-ceiling behaviour.
    pub fn set_learned_fuel_ceilings(&mut self, ceilings: HashMap<String, u64>) {
        self.learned_fuel_ceilings = ceilings;
    }

    /// Resolve a node's effective `max_fuel` — the single decision point shared
    /// by every dispatch path (single-node, pipeline step, loop body).
    ///
    /// Precedence: an explicit `config_override` (graph-JSON `max_fuel`) or the
    /// module default forms the **baseline**; the adaptive learned ceiling is
    /// then applied as a FLOOR (`max(baseline, learned)`) so it can only RAISE
    /// the ceiling to cover observed demand, never lower a deliberately-set
    /// value. The result is clamped to the engine-wide `max_fuel_per_node`
    /// ceiling. When no learned value exists for the node the result equals the
    /// pre-adaptive `baseline.min(max_fuel_per_node)`, byte-for-byte.
    pub(crate) fn resolve_node_max_fuel(
        &self,
        node_id: &Uuid,
        config_override: Option<u64>,
        module_default: u64,
    ) -> u64 {
        let baseline = config_override.unwrap_or(module_default);
        let learned = self
            .node_labels
            .get(node_id)
            .and_then(|label| self.learned_fuel_ceilings.get(label))
            .copied()
            .unwrap_or(0);
        baseline.max(learned).min(self.max_fuel_per_node)
    }

    /// Extract a node's graph-JSON `max_fuel` override from its stored
    /// [`node_configs`](Self::node_configs) entry — the whole `data` object
    /// copied in verbatim during graph load (`parse_graph_document`). Returns
    /// `None` when the node carries no numeric `max_fuel`, so the caller falls
    /// back to the module-row default through [`resolve_node_max_fuel`].
    ///
    /// The single-node dispatch path reads `max_fuel` out of its *merged*
    /// `module_config` (module-artifact config + node data) inline; the
    /// loop-body path has no such merge step, so it routes through this helper.
    /// Shared by the loop-body dispatch site and its unit test so the override
    /// extraction can't silently drift.
    pub(crate) fn node_config_max_fuel(&self, node_id: &Uuid) -> Option<u64> {
        self.node_configs
            .get(node_id)
            .and_then(|cfg| cfg.get("max_fuel"))
            .and_then(|v| v.as_u64())
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

    /// Inject the ops-alerts read port (powers the `ops_alerts_digest`
    /// system node). Wired by the controller engine builder; absent in
    /// out-of-tree consumers, where the node degrades to an
    /// unavailable-envelope output.
    pub fn set_ops_alerts_reader(
        &mut self,
        reader: Arc<dyn talos_workflow_engine_core::OpsAlertsReader>,
    ) {
        self.ops_alerts_reader = Some(reader);
    }

    /// Inject the pending-approvals read port (powers the
    /// `pending_approvals` system node). Wired by the controller engine
    /// builder; absent in out-of-tree consumers, where the node degrades
    /// to an unavailable-envelope output.
    pub fn set_pending_approvals_reader(
        &mut self,
        reader: Arc<dyn talos_workflow_engine_core::PendingApprovalsReader>,
    ) {
        self.pending_approvals_reader = Some(reader);
    }

    /// Inject the assistant-report read port (powers the
    /// `assistant_report` system node). Wired by the controller engine
    /// builder; absent in out-of-tree consumers, where the node degrades
    /// to an unavailable-envelope output.
    pub fn set_assistant_report_reader(
        &mut self,
        reader: Arc<dyn talos_workflow_engine_core::AssistantReportReader>,
    ) {
        self.assistant_report_reader = Some(reader);
    }

    /// Inject the operator-digest read port (powers the `operator_digest`
    /// system node — the autonomy cockpit). Wired by the controller engine
    /// builder; absent in out-of-tree consumers, where the node degrades to
    /// an unavailable-envelope output.
    pub fn set_operator_digest_reader(
        &mut self,
        reader: Arc<dyn talos_workflow_engine_core::OperatorDigestReader>,
    ) {
        self.operator_digest_reader = Some(reader);
    }

    /// Inject the judge-score write port (records observe-only `Judge` /
    /// `InlineJudge` verdicts for the weekly `assistant_report` node).
    /// Wired by the controller engine builder; absent in out-of-tree
    /// consumers, where judge verdicts are simply not recorded.
    pub fn set_judge_score_recorder(
        &mut self,
        recorder: Arc<dyn talos_workflow_engine_core::JudgeScoreRecorder>,
    ) {
        self.judge_score_recorder = Some(recorder);
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

    /// Detach the execution-event sink.
    ///
    /// Used by [`Self::execute_subworkflow_graph`]: a sub-workflow runs
    /// under a SYNTHETIC execution id (`Uuid::new_v4()`) that has no
    /// `workflow_executions` row, so persisting per-node events would
    /// violate `execution_events_execution_id_fkey` on EVERY event. The
    /// default `PostgresEventSink` FKs `execution_id` to
    /// `workflow_executions`; pre-fix the sub-engine inherited the
    /// parent's persisting sink via `adapter_set`, then logged a WARN and
    /// dropped every inner event — pure log noise plus a wasted failed DB
    /// round-trip per event, with zero rows ever persisted. Detaching
    /// makes the (already-effective) no-persist behaviour explicit and
    /// cheap.
    ///
    /// Cost attribution and `__memory_write__` persistence are unaffected:
    /// `execution_cost_rollup` has no FK to `workflow_executions` (so
    /// sub-workflow fuel already lands) and memory writes are actor-keyed
    /// — only the FK-bound event sink is the problem. If per-inner-node
    /// event observability is ever wanted, attribute events to the PARENT
    /// execution id with namespaced node ids rather than re-attaching this
    /// FK-doomed sink.
    pub(crate) fn clear_event_sink(&mut self) {
        self.event_sink = None;
    }

    /// Replace the default post-completion hook. Tests use this to
    /// capture per-node outputs without exercising fuel rollup or
    /// actor-memory persistence.
    pub fn set_node_hook(&mut self, hook: Arc<dyn NodeLifecycleHook>) {
        self.node_hook = Some(hook);
    }

    /// Enable opt-in per-node checkpointing on THIS (top-level) engine.
    ///
    /// After every `every_n`-th node completion, a snapshot of all
    /// completed-node outputs is best-effort persisted via `store` so an
    /// interrupted run can resume from the last checkpoint. `every_n == 0`
    /// is a no-op (leaves checkpointing disabled). Call only on the
    /// top-level engine — sub-workflow engines never inherit this (see
    /// [`CheckpointConfig`]). Safe to leave unset: the default is exactly
    /// today's no-checkpoint behaviour.
    pub fn set_checkpoint_store(&mut self, store: Arc<dyn CheckpointStore>, every_n: usize) {
        if every_n == 0 {
            self.checkpoint = None;
            return;
        }
        self.checkpoint = Some(CheckpointConfig {
            store,
            every_n,
            dirty: std::sync::atomic::AtomicUsize::new(0),
        });
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

    /// Stamp the blanket network-egress scope override. Called by
    /// `talos_engine::actor_binding::apply_actor_to_engine` from
    /// `actors.egress_scope`. `None` = tier-derived default at the worker.
    pub fn set_egress_scope(&mut self, scope: Option<talos_workflow_engine_core::EgressScope>) {
        self.egress_scope = scope;
    }

    /// Stamp the data-mutation ceiling. Called by
    /// `talos_engine::actor_binding::apply_actor_to_engine` from
    /// `actors.max_write_ceiling` before `run()` / `run_with_seed()`.
    pub fn set_max_write_ceiling(&mut self, ceiling: talos_workflow_engine_core::WriteCeiling) {
        self.max_write_ceiling = ceiling;
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
}
