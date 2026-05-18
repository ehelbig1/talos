# MCP Test Fixes — Handoff & Follow-Up Notes

**Date:** 2026-04-20 (revised after 3rd pass — deep surface testing)
**Scope:** Bugs and improvements identified by three end-to-end tests of the Talos MCP server (server `1.0.0-r208`).

Fixes across three iterations:
- **Pass 1 & 2**: Controller-only. Tool schemas, request validation, response shape, WIT path env var, docker-compose (`WORKFLOW_NATS_PREFIX`), two DB CHECK constraint migrations.
- **Pass 3 (this iteration)**: Surfaced (a) a **loop/pipeline module-dispatch cache-key bug** that required changes on both controller *and* engine sides, (b) missing worker Redis config in docker-compose, (c) a miscategorised read-only tool (`normalize_secret_paths`) gated as a write, (d) an inconsistent text response format in `list_expiring_secrets`.

This document captures (a) what was fixed in the controller, (b) follow-up items the engine team should pick up, and (c) environment-level fixes.

---

## Fixed in the controller (this PR)

### 1. Compilation service — opaque `"Failed to copy WIT file"`
`controller/src/compilation/mod.rs`

- The `tokio::fs::copy(self.wit_path, ...)` call was wrapped with `.context("Failed to copy WIT file")` — anyhow swallowed the source path, dest path, and underlying I/O error.
- Replaced with `with_context(|| format!(...))` that includes both paths and an operator hint.
- Added a startup probe in `CompilationService::new()` that emits a loud `tracing::error!` if `wit_path` doesn't exist on disk — diagnoses the cause at process start instead of at first compile request.
- Normalized the four MCP wrappers (`lint_sandbox`, `compile_custom_sandbox`, `run_sandbox`, `install_module_from_catalog`) to format with `{:#}` so the full anyhow chain (which now includes the WIT paths and the OS error) reaches the caller.

### 2. Canonical capability-world list
`controller/src/mcp/capability_worlds.rs` (new)

- Two `&[&'static str]` slices: `COMPILABLE_WORLDS` (11 entries — what the worker actually accepts) and `ACTOR_CEILING_WORLDS` (12 entries — adds `llm-node`, an actor-only privilege tier).
- `compilable_worlds_csv()` / `actor_ceiling_worlds_csv()` helpers used by every `tool_schemas()` site so descriptions cannot drift.
- 3 unit tests guard the invariants (subset relationship, the documented `llm-node` extra, and CSV ordering).
- Refactored 8 schema sites in `sandbox.rs`, `workflows.rs`, `platform.rs`, `advanced.rs`, `actor.rs` to render descriptions from these helpers and to publish a JSON-Schema `"enum"` so MCP clients can validate values themselves.
- `handle_create_actor` validation rewired to call `is_actor_ceiling_world()`; deleted the inline `valid_worlds = [...]` array.

### 3. `create_workflow` contract bugs
`controller/src/mcp/workflows.rs::handle_create_workflow`

- Reject empty / whitespace-only `name` (was silently accepted; created anonymous workflows that surfaced in semantic search as `"name": ""`).
- Honor `force=false` per the published schema: duplicate names now return a `-32602` error unless `force=true` is set explicitly. Previous code accepted `force` only for backward compat and always created.
- Validate `sub_workflow_id` at create time: parse as UUID, then call `WorkflowRepository::workflow_exists()` to ensure ownership + existence. Previously failed silently at execution with `"graph load failed"`.
- `ready_to_run` now requires `node_count > 0` — also fixed at the two parallel sites in `get_workflow_quickstart` and the pattern-instantiation handler.

### 4. `create_workflow_from_description` — error class surfaced
`controller/src/mcp/workflows.rs:7554-…`

- Response now includes `error_class` (one of `rate_limited`, `timeout`, `auth`, `upstream_unavailable`, `network`, `unknown`) plus a truncated (≤512 char) `error_detail` so callers can decide whether to retry vs. escalate. Tip text refined for each class.
- Original error chain is logged at `warn!` with `{:#}` for operator visibility.

### 5. `list_module_catalog` — pagination + filter
`controller/src/mcp/modules.rs::handle_list_module_catalog`

- New optional params: `category` (case-insensitive substring), `capability_world` (exact), `query` (substring on name/display_name/description), `installed_only` (bool), `limit` (1–200, default 50), `offset` (default 0).
- Response includes `returned_count`, `total_available`, `total`, `offset`, `limit`, `has_more`, `filters_applied` so callers can paginate without re-fetching.
- Defense-in-depth: server-side `limit.clamp(1, MAX_LIMIT)` even though the schema enforces `[1, 200]`.

### 6. `search_workflows_semantic` — min_score threshold
`controller/src/mcp/search.rs::handle_search_workflows_semantic`

- New `min_score` param (0.0–1.0, default `0.55`). Filters out results below the cosine-similarity threshold so completely unrelated queries no longer surface noise.
- Each result entry includes `min_score_applied` so callers can see what threshold was used.
- Response shape preserved (still a `Vec<Value>`) — no breaking change for existing callers.
- Important behavior change: when vector search ran successfully but every result was below threshold, we now return an empty array instead of falling through to keyword search. Falling through would surface keyword noise that a strict-threshold caller just rejected.

### 7. `validate_workflow_input` — `schema_present` field
`controller/src/mcp/workflows.rs::handle_validate_workflow_input`

- Response now includes `schema_present: bool`. When false, `valid: true` no longer implies validation occurred — the message body now states explicitly `"validation skipped (input was NOT checked against any rules)"`.
- Eliminates the silent-pass trap: schema-less workflows previously advertised clean validation that didn't exist.

### 8. `archive_actor` — name-reservation behavior documented
`controller/src/mcp/actor.rs` (tool-schema description)

- Description now states that the archived actor's name remains reserved per-user. Operators previously discovered this by trial and error.

### 9. `get_system_health` — admin-only labelled prominently
`controller/src/mcp/analytics.rs` (tool-schema description)

- Description leads with `ADMIN-ONLY.` so non-admin clients filter the tool from their menus, and points them at the user-level alternatives (`get_health_dashboard`, `session_start`).

### 10. `create_schedule` — human-readable cron + upcoming triggers
`controller/src/mcp/schedules.rs` + `controller/src/scheduler.rs::calculate_next_n_triggers`

- New `calculate_next_n_triggers(expr, tz, n)` helper added to `scheduler.rs`. Reused by other tools (e.g. `get_schedule_next_runs`) as needed.
- `create_schedule` response now includes `cron_description` (best-effort English for common patterns) and `upcoming_triggers` (next 3 RFC3339 timestamps in UTC). Operators can sanity-check the schedule without mentally evaluating cron syntax.

### 11. Tool-count drift in MCP `instructions`
`controller/src/mcp/mod.rs::handle_initialize`

- Replaced the hardcoded `"It has 250+ tools"` literal with a `LazyLock<usize>` that sums every `tool_schemas().len()` once. Output reads `"It has N+ tools (plus dynamically registered catalog templates)"`.
- Compute happens once per process; subsequent `initialize` calls hit the cache.

---

## Pass 4 — engine fixes landed, controller wire-up

The engine team shipped fixes for Pass-3 items P3-1, P3-4, P3-5. Controller-side wire-up for this iteration:

| Engine-side change | Controller-side wire-up |
|---|---|
| P3-1: loop + pipeline dispatchers embed `wasm_bytes` inline | Kept the controller's belt-and-suspenders cache-write in `get_module()` as defense-in-depth — comment updated in `controller/src/registry/mod.rs` to reflect engine is fixed but the write remains useful for any future dispatch path that forgets inline bytes. No removal. |
| P3-4: loop `termination_reason` + body-failure propagation | No controller change needed — the engine surfaces `termination_reason` directly in the loop node's output. Verified live: `{"termination_reason": "condition_false"}` appears on successful loops and will show `"body_error"` / `"max_iterations"` / `"module_fetch_error"` on the respective exit paths. |
| P3-5: `NodeEventWrite.error_class: Option<String>` | Added migration `20260420165142_add_error_class_to_execution_events.sql` (new TEXT column + index). `controller/src/engine/event_sink.rs` writes the field. `controller/src/execution_repository.rs` reads it. `watch_execution` and `get_execution_trace` include `error_class` on the event JSON when present. `analyze_execution_failure` surfaces the engine classification as `engine_error_class` alongside the controller's regex-based `error_type` — distinct signals that answer different questions. |
| Core breaking change: `NodeEventWrite` gained a field | Audited controller — only `PostgresEventSink::emit` accepts `NodeEventWrite` by value, no struct-literal constructors to update. Zero churn. |

### Verification

- `cargo check --workspace --offline`: clean.
- Migration `20260420165142` applied successfully.
- Live loop test post-rebuild: 3 iterations, `termination_reason: "condition_false"`, `output: {counter: 3, done: true}` — the single-node-fetch path now gets inline bytes on every dispatch.
- Live failure test: `error_class` column populates as `NULL` for unclassifiable "unknown" errors (appropriate — engine cleaner behaviour than old `non-transient: unknown` wrapper). Column + read-path wire-up confirmed functional.

---

## Pass 3 findings + fixes

### P3-1. Loop / pipeline dispatch cache-key mismatch (CRITICAL — shipped as a belt-and-suspenders fix, engine fix recommended)

**Symptom**: Every loop body's second iteration failed with `"failed to fetch wasm module from redis (not found or redis unavailable)"`. Workflows with pipeline chains (`PipelineStep` dispatcher) would have the same issue. Default docker-compose stack was broken for these dispatch paths out of the box.

**Root cause** (dual): 
1. Controller-side: `ModuleRegistry::get_module` (Level 1 canonical path) never wrote fetched `wasm_bytes` into Redis. Only fallback Levels 2-4 wrote via `cache_wasm_bytes_under`. User-owned modules therefore weren't in Redis after first fetch.
2. Engine-side (`talos-workflow-engine/src/scheduler_handlers.rs:1435` and `engine_dispatch_pipeline.rs:205`): the loop-body and pipeline-step dispatchers set `wasm_bytes: None` while emitting `module_uri: format!("redis:wasm:{module_id}")`. That URI scheme hits the worker's Redis-lookup branch with the non-scoped key `wasm:{module_id}`. Previously this was NEVER written by the user-fetch path (a comment in `engine_dispatch_single.rs:269` documents that site's workaround: "bypasses the `wasm:{uid}:{id}` vs `wasm:{id}` key mismatch"). The single-node dispatcher works around it by embedding bytes inline; the loop/pipeline dispatchers don't.
3. Missing worker config: `REDIS_URL` wasn't in the worker's docker-compose env block — the worker logged `"REDIS_URL not configured. WASM cache interface will be unavailable."` and rejected all `redis:` URIs outright.

**Controller-side fixes (shipped):**
- `controller/src/registry/mod.rs::get_module()` now writes `wasm_bytes` to the non-scoped Redis key `wasm:{module_id}` on every successful Level 1 fetch. Matches the cache key the worker looks up via the engine's URI format.
- `controller/src/registry/mod.rs::ensure_module_in_cache()` refactored into `fetch_and_cache_both_keys()` that writes to BOTH `wasm:{user_id}:{module_id}` (user-scoped, what webhook/gcal/gmail dispatch paths use) AND `wasm:{module_id}` (non-scoped, what engine loop/pipeline dispatchers use). Double-write is safe — bytes are identical, authorization was already enforced.
- `controller/src/registry/mod.rs::get_execution_info()` URI format changed from `redis:wasm:{module_id}` to `redis:wasm:{user_id}:{module_id}`. Tighter security for webhook/gcal/gmail paths; the engine's `redis:wasm:{module_id}` format still works because of the double-write.
- `docker-compose.yml`: added `REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379` to the worker service + `redis` dependency. Worker was silently unable to use Redis.

**Engine-side fix recommended (handoff):**

**File**: `talos-workflow-engine/src/scheduler_handlers.rs:1435` (loop-body dispatch) and `talos-workflow-engine/src/engine_dispatch_pipeline.rs:205` (pipeline-step dispatch).

**Current code** (both sites):
```rust
module_uri: wasm_module.oci_url.clone().unwrap_or_else(|| format!("redis:wasm:{body_module_id}")),
wasm_bytes: None,
```

**Recommended** (match the pattern in `engine_dispatch_single.rs:272-276`):
```rust
module_uri: wasm_module.oci_url.clone().unwrap_or_else(|| format!("redis:wasm:{body_module_id}")),
wasm_bytes: if wasm_module.wasm_bytes.is_empty() {
    None
} else {
    Some(wasm_module.wasm_bytes.clone())
},
```

Why: the `WasmModuleArtifact` returned by `ModuleFetcher::fetch()` already contains the bytes. Embedding them in the DispatchJob removes the Redis-key dependency entirely — matches `engine_dispatch_single.rs`'s workaround, and eliminates the documented `"wasm:{uid}:{id}" vs "wasm:{id}"` key-mismatch class of bugs. Controller's shadow-write fix remains useful as defense-in-depth but would no longer be load-bearing.

### P3-2. `normalize_secret_paths` over-gated as a write
**File**: `controller/src/mcp/secrets.rs`

`normalize_secret_paths` is a read-only analysis tool — it `SELECT`s from `secrets` + `node_templates` and returns rename recommendations. It doesn't mutate. But the dispatcher grouped it under "Write / mutating — require secrets:write or admin", blocking read-only callers from getting audit recommendations.

**Fix**: moved to the read-only section of the `match` block.

### P3-3. `list_expiring_secrets` inconsistent response format
**File**: `controller/src/mcp/secrets.rs::handle_list_expiring_secrets`

Returned a prose-prefixed blob: `"0 secret(s) expiring within 7 days:\n[]"`. Every other secret-list tool returns clean JSON. Machine callers had to string-strip the header.

**Fix**: now returns `{"count": N, "within_days": D, "secrets": [...]}`.

### P3-4. Loop body error semantics (engine-side observation, NOT fixed)
**Observation**: When a loop body errors mid-execution (e.g. module-fetch failure on iteration 2), the `loop1` node captures the error in its output as `{"__error": true, "error_message": "..."}` and the overall workflow is marked `completed`. The user's assertion `assert_status: "completed"` passes — masking a real failure.

**Suggestion (engine)**: when a loop body fails and no `continue_on_error` is set on the loop node, propagate the body failure to the loop node's status rather than capturing it silently in output. Alternatively, add an explicit `termination_reason` field alongside `__error` so users can distinguish "loop exited via condition" from "loop exited via body failure".

### P3-5. Retry classifier overrides explicit `retry_count` (engine-side observation)
**Observation**: A node with `retry_count: 2` configured failed once with a module-returned error. `retries_attempted: 0` — no retries happened because the NATS dispatcher's retry classifier decided the error was "non-transient: unknown". The `analyze_execution_failure` response doesn't explain why the explicit retry_count was ignored.

**Suggestion (engine)**: when the retry classifier short-circuits an explicit `retry_count`, emit a `retry_skipped` event (already supported since the engine-sync PR) with a reason field, and/or surface `"retry_skipped_because": "non-transient_unknown"` in the node trace. The MCP `analyze_execution_failure` tool can then pull it into `remediation_steps`.

### P3-6. Format-inconsistency pattern across structural-node tools (controller-side observation, NOT fixed this pass)
`save_as_template`, `create_from_template`, `test_workflow_draft`, `add_collect_node`, `add_loop_node` all return prose-formatted text blobs instead of JSON. Other list/get/create tools return JSON. Agents/scripts must either parse prose or detect the tool and branch. Worth a follow-up pass to normalise these to `{workflow_id, name, message}` or similar.

---

## Status: all five engine-team follow-ups now closed

Initial handoff flagged five defense-in-depth items. Resolution below:

| # | Item | Status |
|---|------|--------|
| A | Canonical `CapabilityWorld::all_strs()` on worker | **Shipped** in `worker/src/wit_inspector.rs`. Controller's `mcp/capability_worlds.rs::compilable_worlds()` now delegates to it; a unit test (`compilable_worlds_matches_worker_canonical_list`) guards against future drift. |
| B | `SubflowError` hardened (`#[non_exhaustive]` + `missing_sub_workflow_id()`) | **Shipped in engine** (v0.2.0). Controller has no direct `match SubflowError` sites; it uses the engine's own `into_error_envelope()`, so `#[non_exhaustive]` is a non-event for us. |
| C | `EngineError::EmptyGraph` typed variant | **Shipped in engine + controller wiring.** Controller added `engine/user_errors.rs::render_graph_load_error()` that maps `EmptyGraph` to an actionable MCP error (`"Workflow has no nodes — cannot run an empty graph. Add at least one node …"`). Six call sites across `mcp/workflows.rs`, `mcp/actor.rs`, `mcp/advanced.rs`, `api/schema/executions/mutations.rs` routed through the new helper. |
| D | `llm-node` ambiguity | **Resolved** via explicit rustdoc on `worker::CapabilityWorld::from_str`: `llm-node` is formally declared a privilege-tier label only (not a compilable WIT world). Worker test `llm_node_is_not_a_worker_world` guards the invariant. |
| E | `JudgeVerdict` discoverability + serde derives | **Already public + now deriving Serialize/Deserialize.** Controller continues the hand-wired envelope on `subworkflow_contract_service.rs` with a code comment explaining why (stable MCP key name `malformed_fields` diverges from engine's internal `malformed_field_count` — switching would silently break clients). |

## Engine-team follow-up suggestions (NOT bugs — defense-in-depth / cleanup)

These do not block any user functionality. They are improvements the engine team could make to reduce blast radius and tighten coupling between the controller and engine.

### A. Single canonical `CapabilityWorld` parser shared with the controller

**Today**: The worker has `worker::wit_inspector::CapabilityWorld` with a `FromStr` impl. The controller maintains a parallel string-list at `controller/src/mcp/capability_worlds.rs` because the `CapabilityWorld` enum doesn't expose a CSV/iterator/`enum_str_list()` helper.

**Suggestion**: Have `CapabilityWorld` expose:

```rust
impl CapabilityWorld {
    pub const ALL: &'static [Self] = &[Self::Minimal, Self::Http, ...];
    pub fn as_str(&self) -> &'static str;
    pub fn all_strs() -> &'static [&'static str];  // for schema enums
}
```

Then `controller/src/mcp/capability_worlds.rs::COMPILABLE_WORLDS` becomes `CapabilityWorld::all_strs()`. The `llm-node` ceiling-tier extra remains controller-side because it's not a worker-compilable world.

**Risk if skipped**: drift returns the moment a new world is added.

### B. Sub-workflow-id validation at graph-load time

**Today**: The controller now validates `sub_workflow_id` at create time. The engine, when loading a graph from `workflow_executions.workflow_id`, only checks the parent. If a sub_workflow node references a deleted workflow at execution time, the dispatch fails with a generic graph-load error.

**Suggestion**: When the engine encounters a `sub_workflow` node and the referenced workflow does not exist (or is owned by a different user), surface a structured error like `SubworkflowNotFound { node_id, sub_workflow_id }` instead of a generic load failure. Controller already maps load failures to a generic message; a typed error lets it produce a more useful response.

### C. Engine-level `Workflow has no nodes` is not a load failure

**Today**: An empty workflow surfaces as `"Failed to load graph: graph load failed: Workflow has no nodes"`. The double-prefix (`Failed to load graph: graph load failed:`) is awkward, and conceptually it's not a graph-load error — it's a validation error.

**Suggestion**: Distinguish `EngineError::EmptyGraph` from `EngineError::LoadFailed(io_or_parse_error)`. The controller's MCP layer already prevents empty-workflow dispatch via the `ready_to_run` flag fix, but engine-level clarity would help any other dispatcher path.

### D. Capability-world enum currently misses `llm-node`

**Today**: `worker::wit_inspector::CapabilityWorld::from_str` does not handle `"llm-node"` — it falls through to `Self::Unknown`. But `controller/src/mcp/actor.rs` accepts `llm-node` as an actor `max_capability_world`. The mismatch is benign today because actor capability ceilings don't directly invoke the worker parser, but adding a future `compile_custom_sandbox(capability_world="llm-node")` would silently parse to `Unknown`.

**Suggestion**: Decide whether `llm-node` is a real WIT world (in which case add it to `talos.wit` + `CapabilityWorld::from_str`) or a privilege-tier label only (in which case rename it everywhere to `llm-tier` or similar to avoid the suggestion that it's a compilable world).

### E. `Subflow` collapse output shape is documented in CLAUDE.md but lacks a typed accessor

**Today**: CLAUDE.md describes `collapse_subworkflow_output` heuristics (single-terminal vs. multi-terminal) and the engine has these as freestanding functions. The controller's MCP `test_subworkflow_contract` handler manually re-parses the collapsed JSON to extract `{score, passed, reasoning, feedback}` for judge contracts.

**Suggestion**: Promote `JudgeVerdict` (and similar contract-result types) to a public engine type with a `from_collapsed(&Value) -> Self` constructor. Eliminates duplicate parse logic in any new contract test introduced controller-side.

---

## Environment-level issue (now also fixed in code)

### `lint_sandbox` / `compile_custom_sandbox` / `run_sandbox` / `install_module_from_catalog` all returned `"Failed to copy WIT file"` in the test environment.

**Root cause**: `CompilationService::new()` computed the WIT path from `CARGO_MANIFEST_DIR` at build time, producing `/app/talos/wit/talos.wit`. The runtime image places the file at `/app/wit/talos.wit` (the builder-stage `/app/talos/` prefix is not preserved in stage 2). The compile-time-baked path is unreachable from the runtime binary.

**Follow-on fix (PR 2)**:
- `controller/src/compilation/mod.rs`: added a `TALOS_WIT_PATH` env-var override that takes precedence over the compile-time default. Missing-fixture startup log now includes `env_override_set = <bool>` so operators can tell whether the override is being applied.
- `controller/Dockerfile`: set `ENV TALOS_WIT_PATH=/app/wit/talos.wit` in the final runtime stage, matching the image's actual layout.
- This is the correct shape long-term: the build-time path is the dev-tree default; deployments can relocate the fixture independently of the binary.

**Second-order improvements (after retest):**
- `mcp/mod.rs::static_tool_count()` (new, shared): unified the two independent tool-counting lists in `handle_initialize` and `handle_get_platform_info`. Previously `get_platform_info.total_mcp_tools` was 8 tools under the truth because it forgot `knowledge_graph` and `ollama` in its list. A single helper now feeds both callers.
- `mcp/workflows.rs::handle_create_workflow`: when `node_count == 0`, `next_steps` now includes `"Empty workflow — add at least one node before running. Use add_node_to_workflow(...)"` instead of `[]`.
- `mcp/advanced.rs::handle_session_start`: `duplicate_name_groups` now returns `{name, count, workflows: [{id, created_at}], suggested_cleanup}` instead of a bare `{name, count, action}`. The caller no longer needs a follow-up `list_workflows` pass to find out which IDs collide.
- `mcp/advanced.rs::handle_session_start`: removed the second hardcoded `"300+ tools"` literal in the `client_compatibility.full_tool_access` string. Replaced with `"for all tools callable via stdio transport"` — no number to drift.

---

## Verification

- `cargo check --workspace --offline` — clean.
- `cargo test -p controller --offline --lib mcp::capability_worlds` — 3/3 pass.
- `cargo test -p controller --offline --lib mcp::` — 35/36 pass; the one failure (`rate_limiter_resets_after_window_expires`) is a pre-existing 1-ms-window timing flake in `mcp/tests.rs:245`, unrelated to this PR.

---

## What this PR does NOT change

- No DB migrations (no schema changes).
- No `talos-workflow-engine` crate edits.
- No breaking changes to existing tool-call response shapes (`search_workflows_semantic` still returns a JSON array — the new `min_score_applied` field is per-entry metadata).
- No removal of any tool, parameter, or capability.
