# Changelog

All notable changes to `talos-workflow-engine` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0: breaking changes may occur in any minor version. Once the public
API stabilizes alongside `talos-workflow-engine-core`, the crate will move to
1.0 and normal semver applies.

## [Unreleased]

### Fixed

- Loop bodies and pipeline steps no longer force a worker-side Redis
  fetch under the non-scoped `wasm:{module_id}` key. When the fetched
  `WasmModuleArtifact` already carries inline bytes, the loop
  (`scheduler_handlers.rs`) and pipeline (`engine_dispatch_pipeline.rs`)
  dispatchers now embed them in the `DispatchJob` — matching the
  single-node pattern in `engine_dispatch_single.rs`. Eliminates the
  `"failed to fetch wasm module from redis (not found or redis
  unavailable)"` failure that hit every loop body's second iteration
  and any multi-step `PipelineStep` chain. `expected_wasm_hash` is
  now scoped to the URI-fetch path — the envelope HMAC already
  covers inline bytes.
- Loop-body failures no longer silently produce a `completed`
  workflow. `run_loop_iterations` tracks a `termination_reason`
  (`"condition_false"`, `"max_iterations"`, `"body_error"`,
  `"module_fetch_error"`, plus the pre-existing config-miss
  categories) and lifts `__error` / `error_message` to the top level
  of the loop output when the exit was a failure. The scheduler's
  loop-dispatch branch now honors `continue_on_error` the same way
  the capability-dispatch branch does: a body failure propagates to a
  workflow-level error unless the loop node opts in, and still
  captures the error envelope in results when it does.

### Added

- `WorkflowEngineError::EmptyGraph` — new typed variant surfaced when
  `load_from_graph_json` / `load_graph_from_json` parse successfully but
  the document contains no nodes. Previously flowed through the
  `LoadGraph(String)` catch-all with the message `"Workflow has no
  nodes"`; consumers branching on an empty-graph UX now match the
  variant directly instead of substring-matching. The pre-existing
  test in `graph_builder.rs::sync_parser_rejects_empty_nodes` is
  updated accordingly.
- `SubflowError::missing_sub_workflow_id() -> Option<Uuid>` — accessor
  that returns the referenced id when the variant is `GraphNotFound`.
  Lets callers route "sub-workflow deleted" into a structured API
  response without exhaustively matching every variant. `SubflowError`
  itself is now `#[non_exhaustive]`, so downstream `match` arms must
  include a wildcard; future variants (ownership mismatch, schema
  drift, ...) land additively.
- `JudgeVerdict` gains `serde::Serialize` / `serde::Deserialize`, so
  embedders shipping verdicts over an API no longer need to hand-wire
  conversion. The public `from_collapsed` constructor is unchanged
  and stays the recommended entry point for JSON inputs (it
  tolerates missing fields and logs the malformed-field count;
  `Deserialize` is strict).

- `ParallelWorkflowEngine::run_with_trigger_input_transport` (and its
  `_cancellable` sibling) — the fresh-run entry point for workflows
  that expect an external payload at their root. Equivalent to
  `run_with_transport` except the engine installs a synthetic root
  node carrying the caller's `trigger_input`, wires it to every
  current root, and dispatches — a ~20-line controller-side dance
  that previously required hand-rolling now collapses into a single
  call.
  The synthetic-trigger mechanism stays an implementation detail.
  Callers do not learn about the `__trigger__` node, its label, or
  its wiring; a future release can swap to native root-output seeding
  without an API break. Takes `&mut self` because installing the
  trigger mutates the graph; calls are idempotent — the second run
  reuses the existing trigger and only wires edges to any roots that
  appeared since the first call. Integration coverage in
  `tests/trigger_input.rs`: single-root propagation, fan-out to
  multiple roots, idempotency across repeat runs, and cancellation
  on the `_cancellable` variant.
  The existing `execute_subworkflow_graph` path now goes through the
  same private `ensure_trigger_node_wired_to_roots` helper, so the
  sub-workflow dispatch handlers and the new top-level entry point
  cannot drift on trigger wiring. Migration from the old literal
  `"__trigger__"` string to `reserved_keys::TRIGGER` tightens the
  coupling to the documented constant.

### Changed

- **Breaking**: `replace_vault_values` now returns
  `Result<(), VaultResolverError>` instead of `Result<(), String>`.
  `VaultResolverError` is `#[non_exhaustive]` and currently carries a
  single `SecretNotResolved { config_key, vault_path }` variant;
  `Display` still produces the same "secret could not be resolved"
  message consumers may have been parsing, so log output is
  unchanged. Callers matching on the previous `String` error must
  switch to matching on `VaultResolverError::SecretNotResolved` —
  closes the last pre-1.0 stringly-typed error on the public surface.
  The new error type is re-exported from `talos_workflow_engine`
  alongside the existing `replace_vault_values` helper.

### Added

- `SystemNodeKind` JSON round-trip tests for every variant the
  programmatic `WorkflowGraphBuilder` can emit — `Wait`, `SubWorkflow`,
  `Loop`, `Collect`, `Synthesize`, `Verify`, `DynamicDispatch`,
  `CapabilityDispatch`, and (behind `llm-primitives`) `AgentLoop`,
  `Judge`, `InlineJudge`, `Ensemble`, `ConfidenceGate`, `ReActLoop`,
  `ReflectiveRetry`, `LlmDispatch`. Each test builds a node, serializes
  to JSON, parses through `load_graph_from_json`, and asserts the
  decoded kind matches the input — catches any drift between
  `serialize_system_node_kind` and `parse_system_node_kind` /
  `parse_llm_system_node_kind`.
- `docs/graph-json-schema.md` now documents every system-node kind the
  parser accepts. Previously missing: per-kind `data` shapes for
  `collect`, `synthesize`, and `inline_judge`; the kind list at the top
  of the doc also omitted `inline_judge`. `agent_loop` and `react_loop`
  were documented as one combined entry; they now have separate
  sections with a note that `react_loop` is a variant handler.

### Fixed

- `graph_json::validate` no longer emits a spurious "unknown system
  kind" warning for `while_loop`, `repeat_loop`, `fan_in`,
  `error_handler`, or `inline_judge`. The `KNOWN_SYSTEM_KINDS_BASE`
  and `KNOWN_SYSTEM_KINDS_LLM` constants the validator consults had
  drifted out of sync with the parser; a new `all_base_kinds_classified_as_known`
  / `all_llm_kinds_classified_as_known_when_feature_on` test pair
  iterates every entry through the validator so drift surfaces at
  `cargo test` time going forward.
- Root `README.md`, per-crate `talos-workflow-engine/README.md`,
  `talos-workflow-engine-core/src/system_node.rs` module doc, and the
  `llm-primitives` feature comments in both `Cargo.toml` files now
  list `InlineJudge` alongside the other LLM-gated variants, and the
  "19 variants" / "7 LLM/agent-flavored variants" counts update to
  21 / 8 respectively. The root README's "parser accepts a subset"
  claim is replaced with a statement that every variant round-trips
  through both the parser and the programmatic builder.

## [0.2.0] — 2026-04-20

### Added

- `ParallelWorkflowEngine::builder()` returns a fluent
  `ParallelWorkflowEngineBuilder` with chainable `.with_*` methods
  for every adapter slot and tunable limit. The struct-literal route
  (`ParallelWorkflowEngine::new()` followed by 8–12 `engine.set_*()`
  calls) still works; the builder is purely an ergonomic shortcut
  with the same runtime validation contract — missing required
  adapters surface as typed `WorkflowEngineError` variants at
  dispatch time, not at build time.
- `set_max_subflow_depth(usize)` + `WorkflowEngineError::SubflowRecursionLimit { depth, limit }`:
  per-execution recursion guard that prevents a self-referential
  workflow (or a sufficiently deep composition graph) from stack-
  overflowing the reactor. Default cap of 16 (raised via
  `set_max_subflow_depth`); enforced by
  `AdapterSet::into_engine_with_graph` on every sub-workflow
  hydration. Coverage in `tests/subflow_recursion.rs` includes a
  self-referential `SubWorkflow` that previously stack-overflowed
  and now terminates in ~50 ms with a typed error envelope.
  `execute_subworkflow_graph` now routes through
  `into_engine_with_graph` (was the unguarded `new_subengine`) so
  the check actually fires on the engine's hot path.
- `set_cancellation_token(Option<CancellationToken>)` setter for the
  engine. Persists a token that the non-`_cancellable` run methods
  (`run_with_transport`, `run_with_seed_with_transport`) consult
  before each dispatch — eliminates the need for the `_cancellable`
  variants in the common "wire one cancel signal per run lifecycle"
  pattern (graceful shutdown, request-cancellation in an HTTP
  handler, etc.). Inherits through `AdapterSet` so sub-workflow loops
  (`AgentLoop`, `ReActLoop`, `Ensemble`, `ReflectiveRetry`, `Judge`,
  `LlmDispatch`, …) see the same cancel signal — cancelling the
  parent token aborts every running sub-workflow at the next dispatch
  boundary, not just the outer reactor. The `_cancellable` variants
  still take a token as a parameter and ignore the field by design,
  for one-off runs that need to override the engine's persistent
  token.
- `WorkflowGraphStore::resolve_by_name` and `resolve_by_capabilities`
  documentation now names the exact `SystemNodeKind` variants that
  require each override (`DynamicDispatch` and `CapabilityDispatch`
  respectively). The runtime dispatch sites also emit a
  `tracing::warn!` with the likely "you forgot the override" cause
  when the lookup returns `None` — turns the previously-silent
  no-op into a discoverable failure mode.
- `talos-workflow-engine-test-utils::rate_limit::CountingRateLimitStore`
  and `AlwaysAllowRateLimitStore` — in-memory `RateLimitStore` impls
  for downstream integration tests. `CountingRateLimitStore` tracks
  per-module windows + the full call log so consumers can assert on
  metering without rolling their own trait impl. Same lifecycle and
  failure-mode contract as the engine's default — just visible to
  test code.

### Tooling

- New `.github/workflows/bench.yml` runs `scripts/bench-check.sh` on
  every PR touching the engine surface. Restores a Criterion baseline
  from cache (keyed on the merge-base of `main`); on cache miss,
  captures a fresh baseline for the next run. `continue-on-error:
  true` for the initial settling period; flip to false once the cache
  story is reliable.
- `deny.toml` audited and tightened: `yanked = "deny"` (was `warn`),
  expanded section comments documenting every policy choice. The CI
  workflow already runs `cargo deny check` (via
  `EmbarkStudios/cargo-deny-action@v2`).
- Root README gained a "How the crates fit together" section with an
  ASCII dependency diagram — closes the gap where new adopters had to
  read 5 separate `AGENTS.md` files to reconstruct the workspace
  layout.

- `run_with_transport_cancellable` and
  `run_with_seed_with_transport_cancellable`: cancellable variants of
  the existing run methods. Take a
  `tokio_util::sync::CancellationToken`; cancelling the token returns
  `WorkflowEngineError::Cancelled` from the engine reactor without
  waiting for in-flight dispatches to drain. The non-cancellable
  variants are unchanged. Worker-side mid-flight abort is out of
  scope (the engine has no out-of-band channel back to the worker
  pool); consumers that need it carry the
  `DispatchJob::cancellation_token` through their custom
  `NodeDispatcher`. Coverage in `tests/cancellation.rs`.
- `RateLimitStore` trait in `talos-workflow-engine-core`: pluggable
  backing store for the per-module rate-limit counter. Default
  behaviour (no store wired) keeps the existing process-global
  in-memory `DashMap`. Wire a `Some(Arc<MyRedisStore>)` via
  `set_rate_limit_store` for sharded fleets that need the cap to
  hold across rolling deploys and replicas. Failure mode is
  documented as **fail-open**: a store-side error logs a warning and
  allows the dispatch — never block legitimate work because of an
  observability layer being down. Coverage in
  `tests/rate_limit_store.rs`.
- New cookbook doc: [`docs/workflow-graph-store.md`](../docs/workflow-graph-store.md).
  Covers the per-tenant security boundary, the load-bearing
  `get_graphs` override, and a Postgres reference impl.
- New benchmarking workflow under `scripts/bench-baseline.sh` +
  `scripts/bench-check.sh` and documented in
  [`docs/benchmarking.md`](../docs/benchmarking.md). The Criterion
  bench suite ships with regression-detection tooling now —
  `bench-check.sh` exits non-zero when any bench regresses past a
  configurable noise threshold (default ±10%). Wire into CI to gate
  scheduler-touching PRs.
- `dispatch_judge` and `dispatch_inline_judge` now document their
  embedding entry-point use case (one-off scoring outside any
  workflow graph). Cross-referenced from
  `docs/sub-workflow-composition.md`.

- **Lint discipline tightened workspace-wide.** `clippy::doc_markdown`
  is enforced on `talos-workflow-engine` again (the workspace-level
  allow is gone; 36 legacy `engine.rs` violations backticked).
  `unreachable_pub` upgraded from `warn` to `deny` in every crate's
  `Cargo.toml`. `#![deny(missing_docs)]` on `talos-workflow-engine`
  (matching `talos-workflow-engine-core`).

- Four more engine limits promoted to per-engine setters with the
  prior hardcoded values as documented defaults:
  `set_max_prefetch_successors` (8), `set_max_workflow_nodes` (500),
  `set_max_node_output_bytes` (5 MiB), `set_max_fuel_per_node` (50 M).
  Each propagates through `AdapterSet` so sub-workflow loops inherit
  the parent's overrides. Public `DEFAULT_*` constants advertise the
  defaults; `tests/engine_tests.rs` round-trips each setter and
  asserts AdapterSet propagation. The 50M fuel cap is now enforced
  uniformly across single-node, pipeline-chain, and agent-loop
  dispatch paths (previously three separate `min(50_000_000)` calls).
- `tracing::instrument` spans on every sub-workflow handler:
  `dispatch_judge`, `dispatch_inline_judge`, `dispatch_reflective_retry`,
  `execute_subworkflow_graph`, `try_dispatch_agent_loop`,
  `try_dispatch_ensemble`, `try_dispatch_llm_dispatch`,
  `evaluate_confidence_gate`. Each span carries the relevant
  workflow / node ids and `skip_all` on the input arguments so
  plaintext post-template-interpolation secrets never reach a tracing
  sink. Production debugging of nested LLM workflows can now correlate
  log lines without UUID hand-tracing.
- Wire-format snapshot tests for `talos-workflow-job-protocol`
  (`tests/wire_format_snapshots.rs`): byte-level JSON snapshots for
  `EncryptedSecrets`, `JobRequest`, `JobResult`, `PipelineJobRequest`,
  `PipelineJobResult` plus an HMAC-SHA256 signature snapshot for
  `JobRequest`. Catches accidental field reorders, renames, or
  signing-payload format drift before they ship to deployed workers.
- Multi-Wait pause-resume cycle locked in by
  `tests/wait_pause_resume.rs::two_wait_nodes_in_series_pause_resume_pause_resume`.
  Verifies the multi-stage approval pattern (Wait → resume → Wait →
  resume) and the documented "round-trip the snapshot" rule for
  multi-pause workflows.
- `#![deny(missing_docs)]` on `talos-workflow-engine-core`. Every
  public item already had a docstring; the deny gates new additions
  so the trait surface the family depends on can't lose
  documentation in a future PR.

- Pure code refactor: `engine.rs` further decomposed into sibling
  modules. New `engine_dispatch_pipeline.rs` (~545 lines) holds
  `run_pipeline_chain_dispatch` plus `check_rate_limit` and
  `maybe_speculative_prefetch` (both reachable from the chain head).
  New `engine_dispatch_single.rs` (~315 lines) holds
  `run_single_node_dispatch`. `engine.rs` shrank from ~4,914 →
  ~4,295 lines (~13%) while public API and observable behaviour are
  unchanged. Pure code movement; tests are the lock-in. The
  previously-private `MODULE_RATE_LIMITS`, `ensure_rate_limit_eviction_task`,
  and `redact_json` helpers were promoted to `pub(crate)` so the
  extracted modules can call them.
- `clippy::doc_markdown` re-enabled on a per-file basis via inline
  `#![warn(...)]` for `lib.rs`, `error.rs`, `vault_resolver.rs`, the
  two new `engine_dispatch_*` files, and `engine_completion.rs`. The
  legacy `engine.rs` body still has ~36 pre-extraction sites that
  would each need a per-line backticking pass; the workspace-level
  allow keeps it building while new / extracted code is held to the
  higher standard.

- `SystemNodeKind::Wait` is now a first-class pause primitive in the
  scheduler. Reaching a fresh `Wait` node returns a `WorkflowContext`
  with `waiting: true` and a `__waiting__` envelope (carrying
  `node_id`, `execution_id`, and the optional `message`) recorded in
  `results`. Resume by re-running through `run_with_seed_with_transport`
  with the Wait node's id mapped to whatever value should stand in as
  its "output" — successors see the substituted value via gathered
  inputs. Previously `Wait` was parsed but had no engine-side handler;
  the variant fell through to per-node dispatch and failed to fetch
  a non-existent module. End-to-end coverage in
  `tests/wait_pause_resume.rs`. Documented in
  [`docs/checkpoint-lifecycle.md`](../docs/checkpoint-lifecycle.md).
- Three integration guides under `docs/` covering the topics that
  consistently blocked new adopters: writing a custom
  [`NodeDispatcher`](../docs/custom-dispatcher.md), the full
  [checkpoint lifecycle](../docs/checkpoint-lifecycle.md) (`Wait` →
  pause → seeded resume), and
  [composing sub-workflows](../docs/sub-workflow-composition.md) for
  `Judge` / `Ensemble` / `AgentLoop` / `ReflectiveRetry`.
- A second runnable demo at `examples/checkpoint_resume.rs` that wires
  a custom `NodeDispatcher` and an in-memory `CheckpointStore`
  end-to-end across a simulated transient-failure / resume cycle —
  ~280 lines, no NATS, no DB. Complements the dispatch-only
  `hello_workflow.rs` demo with the durable-execution story.
- New typed `WorkflowEngineError::Timeout { secs }` variant promoted
  out of the `Execution(String)` catch-all. Carries the configured
  wall-clock cap so callers can produce specific diagnostics without
  parsing the message body. The two
  `tests/workflow_timeout.rs` cases now `matches!`-pattern on the
  variant.
- Two more typed variants promoted out of `Execution(String)`:
  `WorkflowEngineError::ModuleFetcherMissing` (graph references
  module-backed nodes but no fetcher is wired) and
  `WorkflowEngineError::UserContextRequired` (same scope but no
  `user_id`). Both fail closed at the `run_with_*` boundary instead
  of surfacing as a per-node failure deep inside dispatch — the
  precheck order is documented on `precheck_runnable`. Pure-system-
  node graphs remain runnable without a fetcher / user (lock-in
  guard in `tests/precheck_errors.rs`).
- Pure code refactor: `engine.rs` further decomposed into sibling
  modules. `engine_tests.rs` (~500 lines) holds the inline unit tests
  that previously lived in a `#[cfg(test)] mod tests {}` block;
  `engine_completion.rs` (~450 lines) holds the post-dispatch
  completion handlers (`handle_completed_future`, `handle_node_success`,
  `handle_node_failure`). `engine.rs` shrank from ~5,820 → ~4,910
  lines (~16%). Public API unchanged; the previously-private `redact_str`
  and `apply_fan_in_early_ready` helpers were promoted to `pub(crate)`
  to match the documented intent that engine-internal helpers are
  visible to sibling modules. Most engine struct fields were similarly
  promoted to `pub(crate)` (also matching the existing docstring).
- Property tests for `detect_linear_chains` (5 invariants on random
  DAGs of up to 12 nodes): chains have minimum length 2, are
  pairwise disjoint, every interior is in=1/out=1, every chain edge
  exists in the graph, fan-out nodes are never chain interiors.
  `proptest` is a new dev-dependency; lib code is unchanged.
- Criterion benchmark suite (`benches/scheduler.rs`) covering fan-out
  (N=10/100/1000), linear chain (M=10/100), and seeded resume
  (S=10/100/1000) — for regression detection on scheduling overhead,
  not absolute perf claims. Runs end-to-end against a no-op dispatcher
  so numbers reflect the reactor only. New dev-dependency `criterion`.
- `DispatchJob::builder(execution_id, node_id, module_id, input)`
  fluent constructor in `talos-workflow-engine-core`. The four
  required fields go in upfront so `build()` is infallible; optional
  fields land via chained setters. The struct-literal
  `DispatchJob { ..Default::default() }` form remains supported. New
  `DispatchJobBuilder` type — `#[must_use]`, sealed encrypted-
  secrets pair via a single `encrypted_secrets(ciphertext, nonce)`
  setter so a partial assignment can't desynchronise the pair.
- `SystemNodeKind::InlineJudge { verdict_expr, pass_threshold }` —
  sync, expression-driven verdict that produces the same
  `{score, passed, reasoning, feedback}` envelope shape as a
  sub-workflow `Judge` without authoring a separate workflow. Useful
  when the rubric reduces to a one-line scoring function. Promote to
  a full `Judge` once the rubric grows its own model call. Wired
  through the parser (`inline_judge` kind), serializer
  ([`WorkflowGraphBuilder::add_system_node`]), and a new
  `dispatch_inline_judge` method on the engine.
- `ParallelWorkflowEngine::set_execution_timeout(Option<Duration>)` —
  typed companion to the legacy `set_execution_timeout_secs(u64)`
  setter. `None` disables the wall-clock cap (equivalent to `0` on
  the legacy form); `Some(d)` truncates to whole seconds. The legacy
  form remains for callers that already have a `u64` of seconds at
  hand (graph JSON, env vars, configuration files).
- `ParallelWorkflowEngine::set_agent_loop_max_history(usize)` and
  matching accessor — the sliding-window cap on `__agent_history__`
  injected into `AgentLoop` / `ReActLoop` body iterations is now a
  per-engine setting (default `DEFAULT_AGENT_LOOP_MAX_HISTORY = 20`).
  `0` disables history injection entirely. Propagates through
  `AdapterSet` so sub-workflow loops inherit the parent's setting.
  Previously hard-coded.
- `default_sandbox_root() -> &'static Path` — cross-platform default
  derived from `std::env::temp_dir().join("workflow-engine-sandboxes")`.
  Engine `new()` uses this; the old Linux/macOS-only constant
  `DEFAULT_SANDBOX_ROOT` remains but is `#[deprecated]`. The
  `DEFAULT_SANDBOX_DIR_NAME` const is exported for callers that want
  to derive their own custom paths off the same naming convention.
- `reset_global_rate_limits()` and `global_rate_limit_entry_count()`
  helpers for tests / observability around the process-global
  per-module rate-limit counter. The counter remains static (one per
  process) by design; documented rationale on the static itself.
- Public `WorkflowEngineError` enum (in new `error` module) with
  documented failure-mode variants (`SecretsResolverMissing`,
  `GraphCyclic`), wrappers around lower-level errors (`GraphJson`,
  `Subflow`), and catch-alls (`LoadGraph`, `Execution`).
- New `graph_json` module exposing `SCHEMA_DOC` (the canonical schema
  reference embedded at compile time), `validate` /
  `validate_value` (structural check returning a `GraphSummary`
  without instantiating an engine), and `GraphJsonError` /
  `GraphSummary` types.
- Compile-time `llm-primitives` feature-coherence check in `lib.rs`:
  if a downstream `Cargo.toml` enables the feature on
  `talos-workflow-engine-core` while disabling it on this crate, the
  build fails with a descriptive message instead of silently
  producing un-dispatchable LLM nodes at runtime.
- Runnable end-to-end demo at `examples/hello_workflow.rs`. Wires
  every adapter via `talos-workflow-engine-test-utils`, scripts a
  `NodeDispatcher`, and prints per-node outputs without touching
  NATS or a wasm runtime.
- Graph-JSON parser accepts four new `kind` tags:
  `while_loop`, `repeat_loop`, `fan_in`, `error_handler`. These had
  `SystemNodeKind` variants and engine dispatch paths already but
  previously only round-tripped via imperative construction. See
  `docs/graph-json-schema.md` for their `data` shapes.

### Performance

- Per-module rate-limit eviction moved off the hot path. Previously
  every `check_rate_limit` invocation called
  `MODULE_RATE_LIMITS.len()` and conditionally pruned; now a single
  background tokio task spawned idempotently from
  `ensure_rate_limit_eviction_task` ticks every
  `RATE_LIMIT_EVICTION_INTERVAL_SECS` (60 s) and runs the prune
  call. Spawning is lazy (first-use) so the runtime requirement only
  applies when the engine is actually dispatching.

### Fixed

- Pipeline-chain detection now filters out chains containing system
  nodes. Previously a graph like `module → wait → module` would have
  the entire sequence batched through `dispatch_chain`, which then
  tried to fetch a wasm artifact for the system node (`Wait`,
  `FanIn`, `Collect`, etc.) that has none. The chain dispatch failed
  with a "module not found" error before the per-node handler could
  pause / aggregate / etc. Chains now require every member to be a
  module-backed node with no `SystemNodeKind`. This also restores the
  pause-on-`Wait` contract that batch dispatch otherwise defeats
  (the chain wire format is atomic — there's no way to short-circuit
  mid-chain).

### Changed

- **Breaking**: the `ParallelWorkflowEngine` fields previously marked
  `#[doc(hidden)] pub` — `graph`, `node_map`, `node_labels`,
  `node_configs`, `node_meta`, `execution_timeout_secs`, `dry_run` —
  are now `pub(crate)`. The accessor methods added in the previous
  pass (same names, called as methods) are the canonical public API.
  A new `set_execution_timeout_secs` setter complements the existing
  `set_dry_run` / `set_user_id` setters for mutation. Out-of-tree
  callers still accessing the fields directly will see a compile
  error; migrate to the accessor or setter.
- Internal source reorganisation: `engine.rs` (was 8,967 lines) split
  into `chain_detect` (linear-chain detection), `graph_parser` (JSON →
  `SystemNodeKind` decoding, retry-policy parsing), `sandbox`
  (per-execution scratch dir + RAII guard), `secrets_pipeline` (node
  secret resolution + envelope sealing), `validation` (config pattern
  validator + output sanitizer), and `scheduler_handlers` (per-
  `SystemNodeKind` dispatch methods lifted from the reactor body).
  The scheduler body in `run_with_transport_inner` shrank from 3,025
  lines to ~1,713 (~44%) by extracting 18 handlers: local computation
  (Collect, Synthesize, Verify, FanIn), local iteration (WhileLoop,
  RepeatLoop), sub-workflow dispatch (SubWorkflow, Loop, AgentLoop,
  Judge, Ensemble, ReflectiveRetry, LlmDispatch, ConfidenceGate,
  DynamicDispatch, CapabilityDispatch), and the generic pre-filters
  (Skip-condition, ErrorHandler pattern-match). A shared
  `unblock_successors` helper replaces the ~15 copies of the
  decrement-and-enqueue boilerplate that had drifted between two
  formulations. `DynamicDispatch` and `CapabilityDispatch` share a new
  `run_dispatched_subworkflow` helper (seeded with a `DispatchedOrigin`
  enum) instead of open-coding the same sub-engine-build pattern
  twice.
  The two largest remaining inline blocks — single-node module
  dispatch (~370 lines) and pipeline-chain dispatch (~490 lines) —
  are now named methods on `ParallelWorkflowEngine`:
  `run_single_node_dispatch` and `run_pipeline_chain_dispatch`. Each
  is an `async fn` that the reactor hands to `executing.push` rather
  than an inline `async move` closure; state that used to be cloned
  into the closure is now accessed through `&self` directly. The
  rate-limit check (`check_rate_limit`) and speculative module
  prefetch (`maybe_speculative_prefetch`) are also separate helpers
  so the reactor flow reads as rate-limit → dispatch → prefetch →
  continue.
  Final scheduler body in `run_with_transport_inner`: 3,025 → 459
  lines (~85% reduction). The parallel
  `run_with_seed_with_transport_inner` shrank from 1,967 → 488 lines
  (~75%) and now reuses the same handler methods. Both schedulers
  share `handle_completed_future` for the post-completion fan-out
  (size-guard, sanitize, hook, chain-interior clear, FanIn early-
  ready via `apply_fan_in_early_ready`, edge-condition skipping,
  error-edge routing, `continue_on_error`, and scheduler-fatal
  failure propagation). The public API is unchanged apart from the
  additions noted above.
- **Behavior change**: the two scheduler bodies
  (`run_with_transport_inner` and `run_with_seed_with_transport_inner`,
  previously independent) have been unified into one `run_inner`
  method. Both public entry points (`run_with_transport` and
  `run_with_seed_with_transport`) now delegate to it with
  `initial_results` as the only difference. This resolves three
  observability / safety drifts where the seeded path had features
  the fresh path was silently missing:
    * **`execution_timeout_secs` is now enforced on both paths.**
      Previously only the seeded path wrapped the reactor in
      `tokio::time::timeout`; the fresh path ignored the field
      entirely, meaning a runaway workflow (pathological retry loop,
      stuck `Wait` dispatch, etc.) could hold resources indefinitely
      even when `execution_timeout_secs` was set. Set to `0` to opt
      out of the workflow-level timeout; per-node timeouts remain the
      only safety net in that case. Default is unchanged (300 s).
    * **`WorkflowContext.node_timings` is now populated on both
      paths.** Previously `run_with_transport` returned an empty map;
      only `run_with_seed_with_transport` tracked per-node wall time.
    * **`node_started` events are now emitted on both paths.**
      Previously only the seeded path emitted them.
  Pipeline chain detection still runs only when `initial_results` is
  empty — a seeded resume would otherwise build chains spanning
  already-completed nodes and re-dispatch them.
- **Breaking** (behavior, not signature): `load_from_graph_json`
  (sync, `&Value`) and `load_graph_from_json` (async, `&str`) now share
  a single authoritative parser. The sync entry point previously
  accepted only module nodes and silently dropped system nodes; it now
  parses the full graph shape — system nodes, reserved-key lifts,
  full edge handles, and `execution_timeout_secs`. It also rejects
  graphs with zero nodes (previously it accepted them and produced an
  empty engine), matching the async entry point's behavior. The async
  entry point retains its rate-limit pre-load and sub-workflow graph
  prefetch as post-parse async work; callers who need those should
  keep using the async variant.
- **Breaking**: `WorkflowGraphBuilderError::UnsupportedSystemNodeKind`
  is removed. Every [`SystemNodeKind`] variant now round-trips through
  the builder and the engine's JSON parser — the parser gained
  `while_loop`, `repeat_loop`, `fan_in`, and `error_handler` branches,
  so there is no longer an "unsupported" subset. The enum is now
  `#[non_exhaustive]` with only `UnknownNodeId`; callers who matched
  the removed variant should delete that arm.
- **Breaking**: [`WorkflowGraphBuilder`] now accumulates configuration
  errors and surfaces them at [`build`]. `add_system_node` no longer
  returns `Result<Self, UnsupportedSystemNodeKind>`; it returns `Self`
  and records unsupported variants into the accumulator. The `with_*`
  mutators (`with_skip_condition`, `with_continue_on_error`, `with_retry`)
  that used to silently no-op on unknown node ids now record an
  `UnknownNodeId` error — typos in ids fail loudly at build time instead
  of silently dropping the intended configuration. [`build`] returns
  `Result<JsonValue, BuildError>`; use the new `build_partial()` helper
  to get the graph and errors side-by-side. `UnsupportedSystemNodeKind`
  is replaced by `WorkflowGraphBuilderError::UnsupportedSystemNodeKind`.
- **Breaking**: `ParallelWorkflowEngine::run_with_transport`,
  `run_with_seed_with_transport`, and the sub-workflow dispatch helpers
  now take `Option<WorkerSharedKey>` instead of `Option<Arc<Vec<u8>>>`
  for the worker shared-signing key. `WorkerSharedKey` is a newtype in
  `talos-workflow-engine-core` wrapping `Arc<[u8]>`; it is cheap to
  clone across spawned dispatch tasks, semantically typed, and redacted
  in `Debug` output. Migrate: replace
  `Some(Arc::new(key_bytes))` with
  `Some(WorkerSharedKey::new(key_bytes))`.
- **Breaking**: public methods on `ParallelWorkflowEngine` now
  return `Result<_, WorkflowEngineError>` instead of `Result<_, String>`.
  Affected: `run_with_transport`, `run_with_seed_with_transport`,
  `load_graph_from_json`, `load_from_graph_json`, `add_edge`,
  `validate_config_patterns`, `AdapterSet::into_engine_with_graph`.
  Internal scheduling code keeps its `String`-based error flow; the
  public wrappers wrap once at the boundary.
- **Breaking**: `talos-workflow-engine-nats` `run_with_nats` /
  `run_with_seed_via_nats` propagate the typed error, matching the
  engine signatures they wrap.
- `SystemNodeKind` rustdoc grouped into a "Choosing a variant"
  taxonomy table (iteration / coordination / control flow /
  sub-workflow / runtime dispatch, with LLM groups gated behind
  `llm-primitives`).

## [0.1.0] — Initial release

- `ParallelWorkflowEngine` — DAG scheduler with topological dispatch,
  linear-chain detection and pipeline batching, bounded concurrent fan-out,
  speculative module prefetching, sub-workflow primitives, checkpoint /
  resume, and retry-with-classifier integration.
- `JudgeVerdict`, `SubflowError`, `AdapterSet` — supporting types for
  sub-workflow contracts and adapter wiring.
- `detect_linear_chains` — pure graph function exposed for reuse.
- `validate_config_patterns` — pre-dispatch config validation helper.
- `emit_event_spawn` — fire-and-forget helper around `EventSink::emit`.
- `vault_resolver` — `vault://...` reference extraction + allowlist merge +
  in-place plaintext substitution for per-dispatch secret injection.
- Rhai-backed expression evaluator wired to the
  `talos-workflow-engine-core::ExpressionEvaluator` trait.
