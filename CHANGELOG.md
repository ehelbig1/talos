# Changelog

All notable changes to the Talos platform are documented in this file.

## [Unreleased] — 2026-05-05

### Architectural mandate enforcement

#### Reconcile secrets.rs identifier surface (r306)

Pre-r306, the `secrets` domain had two operator-facing identifiers
that looked interchangeable but weren't: `name` (used by
`set_secret`, `delete_secret`, `set_secret_namespace`,
`set_secret_expiry`, `rotate_secret`) and `key_path` (used by
runtime `vault://…` resolution + the `(namespace, key_path)` unique
constraint). The mismatch produced four real bugs:

* **Non-atomic upsert** in `handle_set_secret`. The pre-r306 path
  called `create_secret` → if the error string contained
  `"duplicate"`/`"unique"`/`"violates"` → called
  `delete_secret_for_upsert` → re-inserted. That parsed error text,
  destroyed-and-recreated (anyone reading in the window saw "not
  found"), and issued a fresh `id` (any FK dependent broke).
* **Silent ambiguity** on every name-keyed mutator. Two secrets
  sharing `name` in the same namespace could both exist (only
  `(namespace, key_path)` was unique), and `delete_secret(name)`
  would mutate one of N with no ORDER BY and no diagnostic.
* **Cross-tenant key_path collision blocking.** The unique
  constraint on `(namespace, key_path)` (no `created_by`) prevented
  two users from independently storing their own
  `anthropic/api_key` — one had to invent a unique path.
* **DB error-text leakage** when the upsert path's magic-string
  match missed (different Postgres error wording across versions).

Fix in five parts:

**1. Migration `20260505200000_secrets_per_user_uniqueness.sql`** —
re-scopes the unique constraint from `(namespace, key_path)` to
`(namespace, key_path, created_by)`. Strictly less restrictive;
every existing row trivially satisfies the new constraint, so no
data migration is needed. Adds `(name, namespace, created_by)`
index for the operator-name-lookup path. Cross-tenant resolution
at runtime is already user-scoped via `created_by = $user_id` in
every read path, so loosening the DB-level uniqueness does NOT
widen the runtime resolution surface.

**2. New `SecretIdentifier` enum + `SecretResolveError` thiserror**
in `talos-secrets-manager/src/identifier.rs`. Three variants:
`Name { name, namespace }` (operator path; ambiguity-detecting),
`KeyPath { key_path, namespace }` (runtime path; per-tenant
unique), `Id(Uuid)` (direct, post-resolve). `SecretResolveError`
carries `NotFound`, `Ambiguous { matches: Vec<Uuid> }` (fail-closed
when more than one row matches a `Name` lookup), and `Internal`
(collapsed to `"Internal error"` so SQL detail can't leak — locked
in by a unit test).

**3. `SecretsManager::resolve_to_id`** — single source of truth for
"given identifier, get id." All three variants are
`created_by`-scoped; cross-tenant resolution is impossible.
Ambiguity is surfaced with the matching IDs (already non-secret
values) so operators can pick `Id` or scope by `KeyPath`.

**4. Atomic upsert + by-id sibling methods.**
`SecretsManager::upsert_secret` does
`INSERT ... ON CONFLICT (namespace, key_path, created_by) DO UPDATE
... RETURNING id, (xmax = 0) AS inserted` — single round-trip,
preserves the original `id`, distinguishes create-vs-update via
Postgres's `xmax` trick, audit-logs the right action label
(`"create"` or `"update"`), invalidates the LLM-keys cache on
every touch (insert OR update — covers rotation). Sibling by-id
methods (`delete_secret_by_id`, `set_secret_namespace_by_id`,
`set_secret_expiry_by_id`, `rotate_secret_value_by_id`) re-assert
`created_by = $user_id` in their WHERE clauses for
defense-in-depth — a stale id from a different scope can't mutate
the caller's row even if the resolver were bypassed.

**5. Operator handler reroute.** `handle_set_secret` now calls
`upsert_secret` directly — drops ~80 LoC of error-string parsing.
`handle_delete_secret`, `handle_set_secret_namespace`,
`handle_set_secret_expiry`, `handle_rotate_secret` each call
`resolve_to_id` first (surfacing `Ambiguous` cleanly) then the
matching by-id method. The legacy name-keyed methods
(`set_secret_namespace`, `set_namespace_by_id`,
`set_secret_expiry_with_reminder`, `delete_secret_by_name`,
`rotate_secret_value`, `delete_secret_for_upsert`) are marked
`#[deprecated]` with migration hints; zero external callers
remain.

**6. Name-collision warning** in `handle_set_secret`. When a new
secret's `(name, namespace)` collides with an existing row that
has a different `key_path`, surface a non-blocking warning naming
both `key_path`s and the existing `id`. Catches the leading cause
of pre-r306 operator confusion at the moment it happens, before
ambiguous state accumulates.

Same architectural pattern as r302/r303/r304/r305, but
intentionally NOT a new crate: `SecretsManager` is already an Arc
in `McpState`, the orchestration is already there, and the right
improvement is a typed identifier + resolver method on the
existing service. New crate would be cargo-culting.

Net result:

* `talos-mcp-handlers/src/secrets.rs`: 1506 → 1516 LoC (the upsert
  collapse saved ~80 LoC; the four resolver routes added ~70).
* `talos-secrets-manager/src/identifier.rs`: 204 LoC (new); 6
  unit tests cover jsonrpc_code stability, internal-error
  redaction, ambiguity-message hint, and constructor sugar.
* `talos-secrets-manager/src/manager.rs`: +290 LoC (resolver +
  atomic upsert + 4 by-id methods + name-collision detector).
* All previous tests passing (33 manager tests including 6 new
  identifier tests, 27 prior cache + audit tests untouched).
* Workspace `cargo check` + clippy + structural lints green.
* Cross-tenant key_path collisions are now possible by design
  (each user can have their own `anthropic/api_key` in
  namespace `default`); runtime resolution remains correctly
  user-scoped.
* Operator ambiguity now fails closed: `delete_secret(name='foo')`
  with two `'foo'` secrets returns `"Multiple secrets matched the
  identifier ([uuid1, uuid2]); specify key_path or id to
  disambiguate"` — operators see the conflict instead of
  silently mutating one of N.

#### Extract SearchService — closes the named-priority extraction list (r305)

New `talos-search-service` crate, owning the embedding pipeline AND
the semantic-search fallback chain that previously lived inline in
`talos-mcp-handlers/src/search.rs` (~580 LoC of primitives + 237 LoC
inline chain handler).

Two surfaces now live in the new crate:

* **Embedding pipeline (free functions)** — `EmbeddingError`,
  `EmbeddingConfig::from_env`, `generate_embedding`,
  `generate_embeddings_batch`, `workflow_embedding_text`,
  `vec_to_pgvector_literal`, `auto_embed_workflow`,
  `embedding_provider_available`, `embedding_provider_status`,
  `refresh_embedding_provider_health`, `PROVIDER_PROBE_INTERVAL`,
  `EMBED_BATCH_MAX`. Stateless from the caller's POV (env-driven
  config + global rate limiter + global health cache); used across
  many call sites (auto-embed-on-publish, scheduled backfill, ad-hoc
  semantic queries, dispatch hooks).
* **`SearchService::search_semantic(input) ->
  Result<SemanticSearchOutcome, SearchError>`** — composes the
  embedding generator with `WorkflowRepository` SQL helpers to run
  the canonical fallback chain: caller-supplied embedding →
  auto-generate via provider → pgvector cosine search (with
  `min_score` threshold) → pg_trgm trigram → ILIKE on first ≥2-char
  word. Pre-extraction this was a 237-LoC handler doing arg parsing,
  embedding, three SQL paths, and three different result-shaping
  branches. Post-extraction the handler is ~75 LoC of arg parsing +
  one service call + response formatting.

Same architectural pattern as `talos-execution-orchestration` (r295),
`talos-workflow-manifest` (r302), `talos-replay-service` (r303), and
`talos-inline-compile-service` (r304):

* `SearchError` thiserror enum with stable JSON-RPC code mapping
  (`InvalidArg` → `-32602`; `Internal` → `-32000`).
* `user_facing_message()` collapses `Internal` to `"Failed to search
  workflows"` — the operator-recognised pre-extraction string. Locked
  in by a unit test that injects a synthesised pgvector-index error
  and asserts redaction.
* Arc-injected `WorkflowRepository`.
* Typed `SemanticSearchInput` + `SemanticSearchOutcome` +
  `SemanticSearchRow` + `MatchMethod` enum (`Vector` / `Trigram` /
  `Keyword`, lowercase serialised — locked in by a unit test
  because dashboards/agents key off these strings).

The pre-extraction `crate::search::*` import paths are preserved as
`pub use` re-exports in `talos-mcp-handlers/src/search.rs`, so
existing call sites in `advanced.rs`, `actor.rs`, `workflows.rs`,
`versions.rs`, `utils.rs`, and `controller/src/main.rs` keep
compiling without churn (14+ call sites unchanged).

Net result:

* `talos-mcp-handlers/src/search.rs` shrinks 1937 → 1200 LoC
  (~740 LoC delete; primitives lifted + handler collapsed).
* New crate is 1154 LoC across 4 files (lib.rs + embedding.rs +
  provider_health.rs + sql_helpers.rs); ~30% is doc comments
  preserved verbatim from the originals so the institutional
  knowledge (r241 batch-shape rationale, EMBEDDING_API_URL=""
  trap, Voyage free-tier RPM gotcha) doesn't move further from
  the code.
* 14 unit tests in `talos-search-service` cover the jsonrpc_code()
  table, internal-error redaction, MatchMethod serialisation,
  SemanticSearchRow shape (skip_serializing_if behaviour for
  `min_score_applied` + `description`), `EmbeddingError::kind()`
  slug stability (metric labels — silent breakage class),
  `truncate_input` char-boundary safety,
  `vec_to_pgvector_literal` formatting, `workflow_embedding_text`
  composition, and the LIKE-escape edge cases (backslash-first
  ordering — silently corrupts patterns if reversed).
* Closes the named-priority extraction list. Remaining structural
  work in CLAUDE.md is `secrets.rs` (semantic reconciliation, not
  mechanical extraction).

Output shape preserved byte-for-byte — existing tooling
(`search_workflows_semantic` MCP tool, `find_similar_workflows`,
ad-hoc agents) sees the same JSON.

#### Extract InlineCompileService (r304)

New `talos-inline-compile-service` crate, owning the wrap → lint →
compile → mirror flow that previously lived inline in
`talos-mcp-handlers/src/workflows.rs::handle_add_node_to_workflow`'s
`rust_code` branch (~340 LoC of capability check + lint + compile +
shared-module guard + permission-drift guard + persistence). The
`module_id` (already-installed) branch is unchanged.

* `InlineCompileService::compile_and_persist(input) ->
  Result<InlineCompileOutcome, InlineCompileError>` — the single
  entry point. Performs (1) capability_world length validation,
  (2) pre-compile actor capability-ceiling check (saves the 30–60 s
  compile when the actor's `max_capability_world` would block the
  result anyway), (3) source wrap with `talos_module!` macro,
  (4) `cargo check`-equivalent lint pre-flight, (5) full WASM
  compile, (6) caller-explicit-vs-default `allowed_hosts`
  resolution, (7) shared-module overwrite guard (refuse if the
  colliding module name is referenced by another workflow),
  (8) permission-drift guard (refuse when the caller passed
  explicit `allowed_hosts` / `allowed_secrets` /
  `allowed_methods` that differ from stored), (9)
  `world_short` + `max_fuel` + content_hash computation, (10)
  `mirror_sandbox_compile_to_modules` upsert.

Same architectural pattern as `talos-execution-orchestration`
(r295), `talos-workflow-manifest` (r302), and `talos-replay-service`
(r303):

* `InlineCompileError` thiserror enum with stable JSON-RPC code
  mapping (`InvalidArg` → `-32602`; `CapabilityCeilingViolation`
  → `-32603`; everything else `-32000`).
* `user_facing_message()` collapses `Internal` to `"Internal error"`
  so the protocol response cannot leak schema, query, or
  runtime-trap detail. Locked in by a unit test that injects a
  synthesised schema-error string and asserts redaction.
* `NoWasmEmitted` keeps the operator-recognised pre-extraction
  string (`"Compiled successfully but no WASM bytes were
  generated"`) — a unit test asserts the byte-for-byte form so a
  refactor can't quietly change the log signature.
* Arc-injected dependencies (`WorkflowRepository`,
  `ModuleRepository`, `CompilationService`, `PgPool` for the
  actor-capability lookup).
* Typed input + outcome structs (`InlineCompileInput`,
  `InlineCompileOutcome`).
* Cross-protocol-ready: the same `Arc` is wired through
  `McpState::inline_compile_service` today, ready to back a
  future GraphQL mutation without duplicating the compile flow.

The MCP handler is now a thin protocol wrapper for the inline
branch:

* Parse + validate `dependencies` with the existing
  `validate_dependencies` helper (returns `-32602` directly so the
  service stays focused on compile + persist).
* Pre-parse `integration_name` and `fuel_budget` via the existing
  `crate::sandbox::parse_*` helpers.
* Build a typed `InlineCompileInput`.
* Dispatch to the service.
* Map `InlineCompileError` back to `mcp_error` via `jsonrpc_code()`
  + `user_facing_message()`.

The post-compile actor-capability-ceiling check at lines 2180–2241
of the pre-extraction handler stays in place — it covers BOTH the
inline-Rust path AND the `module_id` path, so it can't be lifted
into a service that only handles inline-Rust. The pre-compile
check inside the service is purely a fail-fast optimisation; the
post-compile check is the authoritative defense-in-depth gate.

Net result:

* `talos-mcp-handlers/src/workflows.rs::handle_add_node_to_workflow`
  shrinks 766 → 516 LoC (~250 LoC delete from this single handler;
  workflows.rs file as a whole shrinks ~340 LoC including
  surrounding context that was already collapsing).
* 12 unit tests in `talos-inline-compile-service` cover the
  jsonrpc_code() table, the internal-error redaction, the
  pre-extraction error-string lock-ins, and the two pure-helper
  string transforms (`normalise_world_to_node`,
  `world_short_for_persistence` — including the
  `automation-node` → `trusted` legacy synonym).
* Behavior preserved byte-for-byte: every error message — lint
  failure, compile failure, ceiling violation, shared-module
  overwrite, permission drift, no-wasm-emitted — copied verbatim
  from the pre-extraction handler so log greppers and downstream
  tooling see the same strings.

#### Extract ReplayService (r303)

New `talos-replay-service` crate, owning the orchestration that
previously lived inline-and-duplicated across two ~340 LoC handlers
in `talos-mcp-handlers/src/sandbox.rs` (`handle_replay_module_regression`
and `handle_replay_workflow_mode`):

* `ReplayService::replay_module(input) -> Result<ModuleReplayOutcome,
  ReplayError>` — module-mode replay against `module_executions`.
* `ReplayService::replay_workflow_node(input) ->
  Result<WorkflowReplayOutcome, ReplayError>` — workflow-mode replay
  against `workflow_executions.output_data`, with linear-pipeline
  enforcement (fan-in fails closed via `plan_workflow_replay`).

The two paths share one private kernel — `run_replays()` — so the
load-with-template-fallback, secret prefetch, governance/unknown
world rejection, and per-row execute-and-diff loop run from one
implementation. The previous code-of-record literally said "we
duplicate the logic rather than extracting it to avoid widening the
PR — the two handlers are structurally similar and can be unified
in a follow-up refactor"; this is that follow-up.

Same architectural pattern as `talos-execution-orchestration` (r295)
and `talos-workflow-manifest` (r302):

* `ReplayError` thiserror enum with stable JSON-RPC code mapping
  (`InvalidArg` → `-32602`; `NotFound` / `Internal` → `-32000`).
* `user_facing_message()` collapses `Internal` to `"Internal error"`
  so the protocol response cannot leak runtime-trap or schema
  detail. Locked in by a unit test that asserts a synthesised
  schema-error string does not appear in the public message.
* Arc-injected dependencies (`ModuleRegistry`, `WorkflowRepository`,
  `ModuleRepository`, `SecretsManager`, `TalosRuntime`).
* Typed input + outcome structs (`ModuleReplayInput`,
  `WorkflowReplayInput`, `ModuleReplayOutcome`,
  `WorkflowReplayOutcome`, `ReplayResultRow`, `ReplayCounters`,
  `ReplayStatus`).
* Cross-protocol-ready: a single `Arc<ReplayService>` is wired
  through `McpState::replay_service` today, ready to back a future
  GraphQL surface without duplicating logic.

The MCP handler is now a thin protocol wrapper:

* Parse + validate args (mode-specific clamp policies preserved
  verbatim — module-mode rejects out-of-range `limit`/`timeout_secs`
  with the pre-extraction error string; workflow-mode silently
  clamps).
* Build a typed `ModuleReplayInput` or `WorkflowReplayInput`.
* Dispatch to the service.
* Map the typed outcome back into the existing JSON-RPC response
  shape (including the empty-set "message" line and the
  workflow-mode "(root — trigger input)" predecessor placeholder).

Net result:

* `talos-mcp-handlers/src/sandbox.rs` shrinks 3822 → 3354 LoC
  (~470 LoC delete; net replacement with thin wrappers + 1 routing
  comment).
* Replay logic is now testable: 18 unit tests in `talos-replay-service`
  cover the workflow-plan walker (missing nodes, unknown label,
  fan-in, invalid type UUID, root vs. linear chain, default
  config), capability-world rejection (governance / unknown blocked,
  minimal / http allowed), JSON-RPC code stability, internal-error
  message redaction, ignore-field-set composition, and counter
  aggregation. Pre-extraction these were inline closures that no
  test could reach.
* `lookup_node_config_for_module` helper deleted from `sandbox.rs`
  (its only caller is now inside the service; one inline comment
  marks where it lived for grep continuity).

Output shape is byte-for-byte preserved — existing tooling
(`replay_module_regression` MCP tool, downstream `jq`/operator
scripts) sees the same JSON. Verified by inspecting the diff
against the pre-extraction handlers.

#### Extract WorkflowManifestService (r302)

New `talos-workflow-manifest` crate, owning the orchestration that
previously lived inline in `talos-mcp-handlers/src/platform.rs`:

* `WorkflowManifestService::export(user_id) -> Result<ExportOutcome,
  ManifestError>` — parallel workflows + secret-refs fetch,
  module-manifest UUID mapping, canonical `version: 2` manifest
  build.
* `WorkflowManifestService::import(input) -> Result<ImportOutcome,
  ManifestError>` — manifest version + array-cap validation, BUG-59
  module UUID remap, batched name → existing-id lookup, per-row
  upsert with warning aggregation, schedule import, secret-refs
  existence check. Dry-run + live paths both behind one method.

Same architectural pattern as `talos-execution-orchestration` (r295):

* `ManifestError` thiserror enum with stable JSON-RPC code mapping
  (`InvalidArg`/`UnsupportedVersion`/`TooManyWorkflows`/
  `TooManySecretRefs` → `-32602`; `Internal` → `-32000`).
* `user_facing_message()` helper collapses `Internal` to `"Database
  error"` so the protocol response never leaks query/schema details.
* Arc-injected dependencies (`WorkflowRepository`, `ModuleRepository`,
  `SecretsManager`); cross-protocol-ready (the same Arc can back a
  future GraphQL mutation without protocol branching).
* New `crate::utils::manifest_error_to_response(err, req_id)` mapper
  + tracing log on the internal-error path.

`handle_export_platform_state` 87 LoC → 9 LoC (thin wrapper).
`handle_import_platform_state` 290 LoC → 41 LoC. Total
`platform.rs` 1739 → 1429 LoC (-310). Handler responsibilities
collapse to: parse args → call service → format response. Pure
JSON-RPC envelope concerns; zero business logic.

9 unit tests in the new crate cover:
- All five JSON-RPC code mappings
- `user_facing_message()` behavior (especially the security
  invariant that `Internal` collapses to "Database error")
- `ImportOutcome` serialization shape on dry-run vs. live (the
  `serde(skip_serializing_if = "Option::is_none")` discipline that
  preserves the existing response shape exactly).

Behaviour: identical to the pre-extraction handlers — same JSON
shapes, same error codes, same warning aggregation, same dry-run
semantics, same module-UUID remap logic. The dry-run response
adds the `"note"` line via the handler wrapper (matches the
pre-extraction shape exactly).

### Architectural

#### Worker single-publish: eliminate dual-publish at the source (r301)

Architectural follow-up to r300. r300 mitigated the `result_nonce
already seen` failure at the protocol layer (split `verify` into
`verify` + `verify_no_replay` so passive observers don't race the
primary verifier). r301 removes the dual-publish that necessitated
the split — the right architectural fix.

**Before**: worker `publish_result_with_retry` always published every
signed `JobResult` to BOTH the NATS request-reply inbox AND the
global `talos.results.{job_id}` topic, "for logging/audit". The
controller's two consumers (engine dispatcher + audit subscriber)
both verified, racing on the shared `JOB_NONCE_CACHE`. This was
wire amplification (2× NATS bandwidth per result, 2× HMAC verify
CPU) and the source of the bug.

**After**: single publish, branched on dispatcher intent.
* `Some(reply_topic)` (NATS request-reply): worker publishes ONLY to
  the reply inbox. The requester (engine dispatcher, webhooks,
  gmail/gcal) verifies inline and writes durable state through its
  own path. Audit subscriber doesn't see request-reply jobs — but
  it didn't write anything useful for them anyway (workflow-node
  `module_executions` rows are written by `talos-engine`'s
  `record_completed`, with full DLP scrubbing + payload encryption
  the audit subscriber doesn't apply). Net: the audit subscriber's
  UPDATE was redundant for every current dispatch path.
* `None` (true fire-and-forget): worker publishes ONLY to
  `talos.results.{job_id}`. Audit subscriber is the canonical
  landing point. Today every NATS-dispatched code path uses
  request-reply (engine, webhooks, gmail, gcal); `run_sandbox` and
  `test_module` run WASM in-process (no NATS). So this branch is
  dormant — kept for future async work-queue dispatches.

Same single-publish discipline applied to `PipelineJobResult` for
parity. The audit subscriber's `verify_no_replay()` from r300 is
retained as defense-in-depth: if a future change re-introduces
dual-publish or a sibling subscriber, the subscriber stays
safe-by-default. The dispatcher continues to use full `verify()`
(replay protection at the primary).

107 worker tests pass; workspace clean.

### Correctness

#### Fix every-workflow-fails post-deploy regression (r300)

**Symptom**: Every `test_workflow` and `trigger_workflow` execution
failed with `Job result signature verification failed: result_nonce
already seen (replay attempt within 300-second window)` after the
r294 vault-bootstrap rollout. Affected fresh workflows that had
never run before, ruling out cached state.

**Root cause**: dual-publish + dual-verify of the same `JobResult`
against a shared replay cache.

* The worker `publish_result_with_retry` (worker/src/main.rs:305)
  always publishes the same signed `JobResult` to **two** NATS
  subjects: the request-reply inbox AND `talos.results.{job_id}`
  (the latter "for logging/audit").
* The controller process has **two** verifiers that both call
  `JobResult::verify(key, 300)`:
    - `talos-workflow-engine-nats/dispatcher.rs:198` — the engine
      dispatch path consuming the reply.
    - `controller/src/main.rs:2246` — the subscriber on
      `talos.results.*` updating `module_executions` status.
* Both share the process-local `JOB_NONCE_CACHE` static in
  `talos-workflow-job-protocol`. Whichever runs second hits
  "already seen". The race blocks the dispatcher → engine returns
  the result-verify error → node fails → workflow fails.

The `verify()` call is gated on `worker_shared_key.is_some()`. Pre-
r294 vault bootstrap was unstable; `WORKER_SHARED_KEY` likely
loaded as `None` in production and both verifiers became no-ops.
Post-r294 the key loads reliably, both verifiers fire, and the
cache races. The bug has been latent in the design from initial
commit; r294 made it observable.

**Fix**: split the protocol API along the security boundary:

* `JobResult::verify(key, max_age_secs)` — full check (HMAC +
  freshness window + replay-cache record). Used at the **primary
  action point** — the place where the message is converted into a
  side effect that would be wrong to apply twice. There must be
  EXACTLY ONE primary verifier per `JobResult` per controller
  process.
* `JobResult::verify_no_replay(key, max_age_secs)` — HMAC +
  freshness only, no cache touch. Used at **passive observer**
  call sites. HMAC continues to gate forgery; freshness continues
  to gate stale-replay; the within-window-replay primitive is
  enforced exactly once, by the primary.

The `talos.results.*` subscriber is migrated to
`verify_no_replay()` — its only side effect is an idempotent
`UPDATE module_executions` so within-window-replay would be a
no-op. The dispatcher continues to use `verify()`. Seven new
unit tests in `talos-workflow-job-protocol` lock in:
- `verify_no_replay_accepts_repeated_calls`
- `verify_no_replay_rejects_tampered_signature` / `_wrong_key` /
  `_malformed_nonce` (HMAC + freshness still enforced)
- `primary_verify_then_secondary_verify_no_replay_both_succeed`
  (the regression case for the dispatch+subscriber pattern)
- `primary_verify_still_rejects_actual_replay` (replay protection
  intact at the primary path — the security invariant didn't
  weaken)
- `verify_no_replay_does_not_pollute_cache_for_subsequent_verify`

### Architectural mandate enforcement

#### Pause-gate + actor-id parse dedup (r299)

Two more pure helpers replacing duplicated boilerplate across nine
sites in `talos-mcp-handlers`:

* `crate::utils::enforce_executions_not_paused(repo, req_id) -> Result<(), JsonRpcResponse>`
  — replaces five copies of the 12-line `is_execution_paused` match
  block in `workflows.rs` (`handle_test_workflow_draft`,
  `handle_call_workflow`, `handle_bulk_trigger_workflow`,
  `handle_trigger_workflow_as_actors`, `handle_test_workflow`). Same
  canonical operator-facing message; same DB-error logging on the
  repo-failure path. The single site in `executions.rs` was left
  alone — it uses `execution_repo` (different repo, intentionally
  silent on err via `unwrap_or(false)`), divergent semantics.

* `crate::utils::parse_optional_actor_id(args) -> Option<Uuid>` —
  replaces five copies of the 4-line `args.get("actor_id").or_else(||
  args.get("agent_id")).and_then(...)` chain in `workflows.rs`
  (`handle_create_workflow`, `handle_trigger_workflow`,
  `handle_test_workflow_draft`, `handle_test_workflow`) and
  `executions.rs` (`handle_enqueue_workflow`). Single source of
  truth for the canonical-vs-legacy key convention.

Net effect:
- `workflows.rs` 9455 → 9394 LoC (-61).
- `executions.rs` reduced 4-line chain to one helper call.

#### test/dispatch handler dedup — payload size, lifecycle gate, assertion build (r298)

Three pure helpers extracted, removing duplicated boilerplate across
seven sites in `talos-mcp-handlers/src/workflows.rs`:

* `crate::utils::enforce_payload_size_limit(payload, req_id) -> Result<(), JsonRpcResponse>`
  — replaces five copies of the inline 1 MB serialized-input cap
  (`handle_test_workflow_draft`, `handle_call_workflow`,
  `handle_bulk_trigger_workflow`, `handle_test_subworkflow_contract`,
  `handle_test_workflow`). Same canonical error message + `-32602`
  code, single source of truth.

* `crate::utils::actor_dispatch_lifecycle_to_response(result, req_id, log_context) -> Result<(), JsonRpcResponse>`
  — replaces two copies of the 25-line `match` over
  `ActorDispatchLifecycle` (Ok / Archived / Terminated / NotFound /
  Err) in `handle_test_workflow_draft` and `handle_test_workflow`.
  `log_context` flows into the DB-error tracing line so operators can
  still distinguish call sites in logs.

* `talos_workflow_validation::build_test_assertions(actual_status, expected_status, duration_ms, max_duration, output, expected_contains) -> (Vec<Value>, bool)`
  — composes the three currently-supported test assertion kinds
  (status match, max duration, output_contains) into the canonical
  shape. Replaces 50 LoC of inline assertion-building in
  `handle_test_workflow`. 11 unit tests cover each path independently
  (status pass/fail, duration omitted/within/over, output_contains
  top-level/nested/numeric-aware/missing-key/value-mismatch, full
  three-assertion compose).

Net effect:
- `talos-mcp-handlers/src/workflows.rs` 9573 → 9455 LoC (-118).
- 11 new unit tests in `talos-workflow-validation` covering the
  assertion builder; existing `lookup_test_output_key` and
  `json_values_equal_numeric_aware` continue to be tested
  independently — the new helper just composes them.

#### handle_add_node_to_workflow + handle_compile_custom_sandbox dedup (r297)

Six pure helpers extracted into `talos-workflow-creation-helpers`,
removing duplicated inline-Rust compile logic between three sites:

* `wrap_rust_code_with_talos_module(rust_code, capability_world)` —
  injects `#[talos_sdk_macros::talos_module(world = "...")]` before
  `fn run(`. Targets `fn run` specifically (not the first fn) so
  helper functions defined before `run` aren't accidentally
  annotated. Detects four already-wrapped markers
  (`#[talos_node`, `#[talos_module`, `talos_sdk_macros::talos_*`,
  `wit_bindgen::generate!`) and passes through unchanged. Replaces
  three near-identical 25-line blocks (one in `add_node_to_workflow`,
  two in `sandbox.rs` — `compile_custom_sandbox` and `run_sandbox`).

* `resolve_default_allowed_hosts(world, explicit)` — returns `["*"]`
  for network-capable worlds (containing `http`/`network`/`secrets`/
  `automation`/`database`) when caller didn't specify, `[]`
  otherwise. Replaces the 14-line match block in `add_node_to_workflow`.

* `format_shared_module_overwrite_error(node_id, existing_id, others)` —
  formats the "Refusing to overwrite shared module" error with first-5
  preview + "and N more" summary line. Replaces ~30 lines of inline
  `format!` + preview-building.

* `StoredPermissions { allowed_hosts, allowed_secrets, allowed_methods }`
  + `compute_permission_drift(explicit_h, explicit_s, explicit_m, &stored)`
  + `format_permission_drift_error(node_id, existing_id, drift_lines)` —
  triple of helpers that replaces ~60 lines of permission-drift
  detection. Ordering- AND duplicate-insensitive comparison preserved
  from the original `perm_lists_equal` (caller passing
  `["api", "api"]` against stored `["api"]` is not drift).

Net effect:
- `handle_add_node_to_workflow` 844 → 767 LoC
- `sandbox.rs` 3867 → 3822 LoC (two duplicate wrap blocks deduped)
- 16 new unit tests covering each helper's surface (already-wrapped
  passthrough for each marker, fn-run injection vs. helper-fn
  preservation, world keyword coverage, drift sort-order
  independence, dedup behavior, preview truncation).

The two `fn perm_lists_equal` / `fn fmt_perm_list` helpers at the top
of `talos-mcp-handlers/src/workflows.rs` were dead after wiring and
have been removed; `compute_permission_drift` is the sole canonical
implementation now.

### Correctness

#### TOCTOU window closed in trigger() concurrency-limit gate (r296)

Pre-r296 the orchestration service's `trigger()` did
`count_running_executions(...)` and `create_execution_with_lineage(...)`
as two separate SQL statements. Two parallel triggers against a
workflow at its `max_concurrent_executions` limit could both pass
the count check, then both INSERT, exceeding the cap. The GraphQL
`triggerWorkflow` path already had the fix (its own inline
transaction); the MCP path silently shipped the bug.

New `WorkflowRepository::create_execution_under_concurrency_limit`
does both in one transaction:

  BEGIN; SELECT max_concurrent_executions FROM workflows WHERE
  id = $1 FOR UPDATE; (count check inside same tx); INSERT or
  ROLLBACK with `ConcurrencyAdmission::LimitReached`; COMMIT.

The FOR UPDATE row lock means a second trigger blocks until ours
commits — at which point its COUNT sees the new row. Workflows
with no limit (`max_concurrent_executions = NULL`) skip the count
check; the lock is briefly held for the INSERT, consistent with
the GraphQL path.

`talos-execution-orchestration::trigger()` routes through the new
helper. Authorization promoted earlier so it still fails fast
before any DB writes.

### Architectural mandate enforcement

#### handle_add_node_to_workflow phase-1 decomposition (r296)

Pulled four pure-logic blocks out of the largest handler in the
workspace (983 LoC, top of the architectural-mandate backlog) into
`talos-workflow-creation-helpers`:

  - **`detect_template_interpolation_warnings(config)`** — walks
    string-valued config fields for `{{key}}` interpolations,
    surfaces operator-actionable warnings. Reusable from
    `update_node_config` (next pass).
  - **`validate_config_field_types(config, schema)`** — JSON-schema
    type check (integer/number/boolean/array/object; string and
    unspecified lenient, matching historical behaviour). Returns
    single-string formatted error listing every mismatch.
  - **`upsert_node_edges(edges, node_id, from, to)`** — append-or-
    update edges with bypass-edge removal when both ends are
    specified. Idempotent on re-call.
  - **`build_add_node_payload(AddNodeInputs<'_>)`** — node JSON
    construction with field-preservation rules: caller-arg >
    existing-node-value > template_max_retries default. Catches the
    human-approval-class regression where template_max_retries=0
    would silently inherit the engine's `unwrap_or(2)` and trigger
    retry storms on rejection.

15 new unit tests covering object-recursion, array opacity, type
mismatch detection, edge dedup, bypass-edge removal, field
preservation across re-binds. 88 total tests in the helpers crate,
all green. Zero DB / mocks / async required for any of them.

Handler reduction: 983 → 844 LoC (139 LoC pulled out, all fully
unit-tested in isolation). Phase 2 (deferred) is the inline-compile
dispatch path (~330 LoC) — substantially bigger lift because it
touches the compilation service, module repository, and several
actor-helper imports. Worth its own focused commit.

#### ExecutionOrchestrationService extraction (r295)

Pulled trigger / replay / replay_with_input / retry orchestration out of the inline MCP handlers and into a new `talos-execution-orchestration` crate. Net code motion:

  - `talos-mcp-handlers/src/executions.rs::handle_retry_execution` 137 → 27 LoC
  - `talos-mcp-handlers/src/executions.rs::handle_replay_execution` 190 → 28 LoC
  - `talos-mcp-handlers/src/executions.rs::handle_replay_execution_with_input` 197 → 33 LoC
  - `talos-mcp-handlers/src/workflows.rs::handle_trigger_workflow` 493 → 122 LoC
  - **Total handler reduction**: 1,017 → 210 LoC. The 800 LoC of orchestration logic now lives in one cohesive service, not duplicated across four call sites.

Service surface:
  - `ExecutionOrchestrationService::new(workflow_repo, execution_repo, actor_repo, secrets_manager, registry, nats_client, worker_shared_key, db_pool)`
  - Four public methods returning typed outcomes: `retry → ExecutionOutcome`, `replay → ExecutionOutcome`, `replay_with_input → ExecutionOutcome`, `trigger → TriggerOutcome` (Dispatched | DryRun, since trigger supports a dry-run validation early-return).
  - `OrchestrationError` thiserror enum with stable `jsonrpc_code()` mapping (-32602 / -32001 / -32003 / -32004 / -32005 / -32000) — tripwire-tested so code rotation breaks loudly.
  - Pure helpers extracted with full unit-test coverage: `deep_merge` (9 tests covering object recursion, array opacity, null replacement, scalar↔object swaps), `count_memory_write_nodes` (7 tests covering data/config dual-shape, malformed JSON safety, empty-string falsy handling), `OrchestrationError::jsonrpc_code` stability tripwire, `REPLAY_OVERRIDE_MAX_BYTES` ceiling tripwire — 19 tests, 0 DB required.

Cross-protocol consumer wiring:
  - Single `Arc<ExecutionOrchestrationService>` constructed in `controller/src/main.rs` and threaded into both the MCP router (`McpState::execution_orchestration_service`) and the GraphQL schema (`ctx.data::<Arc<...>>`). Both protocols pull the same instance; no duplication of engine builder, NATS dispatch, or auth gate.
  - `execution_repo` and `actor_repo` construction hoisted up beside `workflow_repo`/`module_repo` so both repositories are in scope when the service is constructed (was: late construction just before `create_router`).
  - `orchestration_error_to_response` helper in `talos-mcp-handlers/utils.rs` maps typed errors back to MCP responses with byte-identical historical user-facing messages (e.g. "Execution queue is paused. Use resume_executions to re-enable."). Internal/Database variants log full detail server-side and return generic "Internal server error" — no DB strings on the wire.

Behaviour preserved verbatim (post-extraction parity):
  - All authorization gates: pause check → workflow load → enabled check → graph load → concurrency limit → `authorize_workflow_trigger` (capability ceiling + actor budget + graph ownership) → input schema validation → input size cap (1 MiB) → optional actor-context injection → trigger-type allowlist → parent + root execution lineage → execution row creation → reuse-event analytics → audit log.
  - All terminal-status semantics: spawned dispatch with `TALOS_MAX_CONCURRENT_EXECUTIONS` semaphore (default 3) → on success: `mark_execution_completed` + scratchpad trace upsert if actor bound (Phase 5.2) → on failure: `mark_execution_failed` + `cancel_running_module_executions` (defence in depth atop the DB trigger) + `publish_execution_failure_alert` + `dispatch_failure_webhook` (with SSRF re-validation at fire time per r287).
  - WorkerSharedKey re-exported from the service crate so consumers don't reach into engine-core directly.

Deferred follow-up:
  - **GraphQL `triggerWorkflow` mutation cutover**. The mutation streams `ExecutionEvent`s via a `broadcast::Sender` during dispatch — pushing event emission into the service would couple it to GraphQL's event shape, so the cutover is deferred to a focused follow-up. The mutation already routes through `talos_workflow_authorization::authorize_workflow_trigger` (r293) so it has the canonical RBAC gate; only the inline-vs-service orchestration shape differs.

#### Vault least-privilege controller token (r294) — chart-level fix
- **Chart no longer ships `dev-root` to the controller.** The `vault-init` Job is now a two-container Job:
  - **initContainer `vault-bootstrap`** (vault image) — unseal + transit + KEK + writes a `talos-controller` policy (`transit/encrypt`, `transit/decrypt`, `transit/keys/<kek>` only — no token mint, no key rotation, no other engines) + mints an orphan periodic token under that policy. Drops the token to a shared `/tmp` emptyDir.
  - **container `secret-patcher`** (bitnami/kubectl:1.31) — reads the current `VAULT_TOKEN` from the bootstrap Secret. If it's one of the known placeholders (`__pending_vault_init__`, `dev-root`, or empty) it patches the Secret with the new least-privilege token AND triggers a controller rollout so `envFromSecret` picks up the value. Operator-set values are left alone (no clobbering of manual rotations).
- **`install.sh` seeds `__pending_vault_init__`** instead of `dev-root` on fresh installs. Controller's `VaultTransitProvider::from_env` now refuses this sentinel with a clear "vault-init has not yet patched the bootstrap secret" message, alongside the existing `dev-root` guard.
- **Scoped RBAC for the patcher** — Role with `resourceNames` pinning. The vault-init SA can `get`+`patch` the bootstrap Secret and `patch` the controller Deployment, nothing else. Compromise of this SA token cannot read any other Secret in the namespace.
- **Self-healing on `helm upgrade`** — existing deployments still on `dev-root` automatically rotate to `talos-controller` on the next chart apply. No manual `vault token create` + `kubectl patch secret` dance.
- **Closes the deploy footgun** that the r293 dev-root guard surfaced: production deployments shipping a root-policy never-expires token via the bootstrap Secret. With r294 the chart never writes `dev-root` to a Kubernetes Secret in the first place.

#### Post-extraction hardening batch (r293)
- **Worker tier-1 `wit_email::send` gate** — closed the last data-egress gap on the tier-1 ceiling. Tier-1 actors (local-Ollama-only, data must not leave host) could previously fan out workflow output via `wit_email::send` because the host fn lacked the `max_llm_tier == Tier1` refusal that already covered `wit_http`, `wit_graphql`, `wit_webhook`, and `wit_http_stream`. Now logged via `record_capability_denied("email-send", "tier1-egress", ...)`.
- **OCI cache fail-closed without attestation** — `bytes_attested_in_this_run` flag tracks whether the WASM bytes loaded into the worker passed Sigstore + layer-digest verification *in this process run*. A cached blob from a prior verified pull no longer counts; the worker refuses to execute when the flag is false AND `expected_wasm_hash` is unset AND `RUST_ENV=production`. Closes the window where a poisoned Redis cache could feed unverified bytes to wasmtime under an attacker-controlled module URI.
- **Approval-gate webhook SSRF re-validation at fire time** — `talos-engine`'s approval-gate webhook firing now re-runs `check_outbound_url_no_ssrf` before each call AND sets `redirect::Policy::none()` on the reqwest client. Pre-fix, a webhook URL stored before `r285` (non-canonical IPv4 rejection) could fire untouched on every approval, and the default redirect policy let an attacker trampoline via a public-facing 302 to an internal IP. The SSRF helper moved from `talos-mcp-handlers/utils.rs` to a new `talos-http-utils::ssrf` crate so engine layers can use it without a layering inversion.
- **`run_with_trigger_input_via_nats` refuses unsigned dispatch in production** — explicit fail-closed when `worker_shared_key=None` AND `RUST_ENV=production`. Eleven MCP call sites (executions, actor, workflows) converted from silent `.ok()` to `crate::utils::load_worker_shared_key_logged(file!())` so the missing-key case logs an operator-actionable warning at boot rather than producing jobs that fail HMAC verify on the worker side.
- **AEAD nonce CSPRNG parity** — `EncryptedSecrets::encrypt` switched from `thread_rng()` (ChaCha-12) to `OsRng` (getrandom) to match `talos-memory::rpc_auth`. Workspace-wide consistency for audit; removes the ChaCha-12 birthday-bound footnote.
- **JobNonceCache replay protection** — every signed-NATS RPC `verify()` impl in `talos-workflow-job-protocol` (`JobRequest`, `JobResult`, `PipelineJobRequest`, `PipelineJobResult`, `WorkerHeartbeat`) now consults a single-use nonce cache after HMAC verification. Within the freshness window, the same signed bytes can no longer be replayed; second-and-subsequent attempts return a `replay attempt within {N}-second window` error. 200k hard cap with sweep above 1k entries; poison-tolerant Mutex<HashMap>. Sibling repo bump `0.2.0 → 0.3.0` (semver minor — behavior change in published crate).
- **Vault `dev-root` token guard** — `VaultTransitProvider::from_env` refuses to boot in production if `VAULT_TOKEN` equals the chart's seed `dev-root` value, and warns at startup in non-prod. Closes the "shipped Helm dev defaults to prod" footgun.
- **GraphQL ↔ MCP RBAC parity (capability ceilings)** — `trigger_workflow` GraphQL mutation now delegates to `talos_workflow_authorization::authorize_workflow_trigger`, which re-verifies the actor's capability ceiling, the broader execution gating, and distinguishes terminal-state vs. ownership rejections. Two GraphQL world-list drift sites unified to canonical `talos_capability_world::ACTOR_CEILING_WORLDS` + `world_rank()`. `enqueue_workflow` MCP handler now matches `set_workflow_actor_id`'s ownership check via `state.actor_repo.get_actor_basic_info(agent_id, user_id)`.

#### Runtime hygiene
- **Watch-channel graceful shutdown** — `bg_shutdown_tx`/`rx` `tokio::sync::watch` channel wired into the LLM-keys sweep, actor-memory TTL sweep, and scheduler. `with_graceful_shutdown` now signals both rpc-subscriber and background workers, eliminating the orphan tasks that survived a SIGTERM and could keep writing after the DB pool was closed.
- **`talos-scheduler::run_with_shutdown(rx)`** — new shutdown-aware entrypoint with `tokio::select!` between scheduler tick and shutdown signal. Old `run()` is a back-compat shim that forwards to the new path with a never-fired signal.
- **SSE event size cap** — `wit_http_stream` enforces `TALOS_SSE_MAX_EVENT_BYTES` (default 1 MiB) on both the per-event buffer and the accumulated `data_lines` collection. Closes a memory-exhaustion DoS via a malicious upstream that streams an arbitrarily large single event.
- **Error-path logging discipline** — 8 `let _ = sqlx::query` sites in `talos-api` workflow mutations and the controller SLA monitor converted to `if let Err(e) = ... { tracing::error!(...) }`. Silent failures on the write path now surface in logs.

#### Supply chain + release gating
- **Release workflow SHA-pinned** — `.github/workflows/release.yml` actions all pinned to specific commit SHAs (checkout, dtolnay/rust-toolchain, docker/login-action, softprops/action-gh-release, actions/upload-artifact, slsa-framework). Closes a tag-poisoning vector where an upstream tag rewrite could inject a malicious build step.
- **`:latest` push gating** — `release.yml` split into `release` job (pushes `:VERSION` only) + `promote-latest` job that runs only after `[release, sign, provenance]` all succeed. A failed Sigstore signing or SLSA provenance attestation no longer leaves a `:latest` pointing at unattested bytes.
- **Cosign + advisory-DB pinning** — both controller and worker Dockerfiles pin `rust:1.91@sha256:...` base images, the cosign binary by sha256 (`8b24b946...`), and `cargo-audit`'s advisory database to a specific git commit (`20377f44...`).
- **`automountServiceAccountToken: false`** on the controller pod's ServiceAccount; kubeconfig file mode `600` (was `644`) in `deploy/k3s/install.sh`.
- **Release artifact size reduction** — `.dockerignore` now excludes `.claude/`, `.codex/`, `docs/`, `observability/`, `deploy/`, `audit.toml`, `deny.toml` from build contexts.

#### Dispatch-time secret-pipeline gap closed (gmail/gcal push notifications)
- **`encrypted_secrets: Default::default()` → `build_dispatch_encrypted_secrets`** in `talos-gmail/src/dispatch.rs` and `talos-google-calendar/src/handlers.rs`. Pre-fix the push-notification dispatch path silently shipped jobs with an empty encrypted-secrets payload — `vault://` header substitution returned `NotFound` and `talos::core::llm::*` host calls failed with `NotConfigured`, but the job still ran. Same class of bug as the 2026-04-16 loop-node dispatch fix.
- **Shared helper in `talos-integration-helpers`** — single canonical implementation that mirrors `ParallelWorkflowEngine::build_encrypted_secrets`. All push-notification integrations now route through it. `WORKER_SHARED_KEY` unavailable, `SecretsManager` missing, or encryption errors all degrade to empty-secrets with a logged warning rather than crashing the dispatch path.

#### Per-protocol RBAC + injection fixes (r282–r289)
- **r282 — workflow-version fetch SQL scoped by user_id** — `WorkflowRepository` queries that previously dropped the user_id filter on the version-fetch path now enforce ownership.
- **r283 — admin-gate Ollama model pull/delete** — pull and delete operations now require platform-admin scope. Previously any authenticated user could remove a model another tenant relied on.
- **r284 — knowledge-graph queries require actor ownership** — graph_query MCP tool now verifies the calling agent owns the actor whose knowledge graph it's reading.
- **r285 — non-canonical IPv4 SSRF rejection** — webhook-target validation now rejects octal, decimal, and dotted-hex IPv4 encodings that previously bypassed the host allowlist.
- **r286 — role-gate run_sandbox by allowed_capabilities** — RBAC parity with `compile_custom_sandbox`. Closed a privilege escalation where any compile-and-execute path could exceed an actor's capability ceiling.
- **r287 — re-validate stored webhook URLs at fire time** — write-time SSRF validation isn't sufficient for URLs stored before a rule change. Background firing now re-validates against the current rule set.
- **r288 — atomic claim on resume_workflow_by_correlation_id** — eliminated a TOCTOU window in the MCP suspension-resume path where two concurrent claims could both succeed.
- **r289 — verify org membership on create_secret org_id** — cross-org resource-injection fix. Mutations accepting `org_id` from caller now gate via `user_writable_org_ids`.
- **r291 — owner promotion via `transfer_ownership` only** — `update_member_role` and `add_member` now refuse `new_role=Owner`. Closed an Admin → Owner self-promotion path.
- **r292 — GraphQL handlers mirror MCP RBAC checks** — actor-ceiling bypass on the GraphQL surface; MCP is the canonical RBAC home and GraphQL had drifted.

### Architectural mandate enforcement

#### Workspace decomposition: controller bin ~95k → ~5.8k LoC
- **92 `talos-*` workspace crates** now own implementation. The controller bin is bootstrap-only — `main.rs` (~4.8k LoC of axum wiring) plus `lib.rs` and ~80 single-line re-export shims. Every former `controller/src/*.rs` module has a canonical home crate; the shims preserve `crate::foo::bar` import paths so existing callers keep resolving.
- **Per-domain repository crates** — `talos-actor-repository`, `talos-advanced-repository`, `talos-analytics-repository`, `talos-execution-repository`, `talos-module-repository`, `talos-workflow-repository`, `talos-webhook-repository`, `talos-schedule-repository`. Repository-per-domain pattern; centralises SQL with one home per concern.
- **Per-domain service crates** — `talos-engine`, `talos-engine-events`, `talos-llm`, `talos-actor-policies`, `talos-actor-scaffold`, `talos-actor-memory-service`, `talos-compilation`, `talos-templates`, `talos-module-templates`, `talos-module-executions`, `talos-registry`, `talos-rpc-subscribers`, `talos-scheduler`, `talos-subworkflow-contract`, `talos-workflow-validation`, `talos-workflow-versions`, `talos-workflow-authorization`, `talos-workflow-creation`, `talos-workflow-creation-helpers`, `talos-execution-result-collector`.
- **Per-protocol crates** — `talos-api` (entire GraphQL surface), `talos-api-docs` (Playground + REST docs), `talos-mcp-handlers` (~56k LoC, 280+ MCP tool handlers, McpState), `talos-ws-auth` (GraphQL-over-WebSocket handshake).
- **Per-integration crates** — `talos-atlassian`, `talos-slack`, `talos-google-calendar`, `talos-gmail`, `talos-integration-helpers` (shared `RenewalFailure` + `looks_like_oauth_failure` between gmail/gcal), `talos-integration-state`, `talos-integrations`, `talos-webhooks`, `talos-continuation-trigger`, `talos-oauth`.
- **Cross-cutting** — `talos-memory-crypto`, `talos-actor-policy-hook`.

#### Zero-raw-sqlx invariant (lint-enforced)
- **0 raw `sqlx::query*` calls in `talos-mcp-handlers/src/*.rs`** (down from 371 originally → 276 mid-spike → 0). Every MCP handler is now a thin wrapper over a typed repository method.
- **`scripts/lint-structural.sh` check 6** fails CI on backslide. Opt-out marker `// allow-mcp-sqlx: <reason>` for documented exceptions. Five other structural checks added: `__agent_context__` regression detection, per-call `SecretsManager::new` outside canonical wiring, `helm template` with default + every-toggle-on render.

#### Service extraction (cross-protocol reuse)
- **`WorkflowCreationService`** — pulled out of a 1,104-LoC MCP handler. Two methods: `create_from_description` (LLM scaffolding + explicit-modules fallback) and `create_from_spec` (declarative node + edge spec with three-path module resolution: UUID / catalog name / inline Rust compilation). Typed outcome enums separate hard infra failures (DB unavailable) from soft semantic outcomes (LLM rate-limited, no modules matched). 31 unit tests defending pure logic that was previously zero-tested.
- **`createWorkflowFromDescription` GraphQL mutation** — first cross-protocol service consumer. Same `WorkflowCreationService` backs both `MCP::handle_create_workflow_from_description` and the new GraphQL mutation. Validates the speculative-reuse argument; the mutation landed without a single line changing in the service crate. 8 projection tests defend the GraphQL response shape.
- **`talos-execution-result-collector`** — pure helpers (`collect_success_output`, `collect_failure_output`) that unify the post-execution result-collection block previously duplicated across 8 dispatch sites. 5 sites converted; 3 (webhooks ×2, continuation-trigger) intentionally kept distinct due to different return-vs-store semantics. DLP-redaction is now a single bottleneck — 2 unit tests defend the secret-leak boundary directly.
- **`HotUpdateService`** — pulled out of `handle_hot_update_module` (530 → 78 LoC). New crate `talos-hot-update-service` owns the recompile + mirror flow behind a single `execute(HotUpdateInput)` method. Pure transformation helpers (`resolve_source`, `wrap_source_with_module_macro`, sandbox vs. compiled fuel cascade, world-short mapping) are unit-tested directly — 21 tests, no DB required. Typed `HotUpdateError` enum maps cleanly to JSON-RPC codes (-32602 vs -32000) so the handler doesn't introspect strings. Subtle pre-extraction behaviors preserved verbatim: sandbox `automation-node → trusted` mapping, Redis DEL across both URI shapes + both id forms (so webhooks don't serve stale bytes), source-wrap skip when `wit_bindgen::generate!` / `talos_*` markers are present.
- **`ModuleRepository::get_max_fuel`** — last raw `sqlx::query_scalar` in `talos-mcp-handlers` lifted into the repository.

### Operational

- **Smoke-test surface unchanged.** `scripts/smoke.sh` continues to gate every public path against a deployed cluster. New crate boundaries are entirely a refactor; no public API surface changed.
- **CI builds in parallel.** Docker controller and worker images now build as separate jobs (`docker-controller` + `docker-worker`); clippy split out of the test job.
- **Dead code removed** — `controller/src/routes.rs` (1,060 LoC, zero callers), `controller/src/secrets/` orphans (845 LoC, already extracted to `talos-secrets-manager`), `audit_ledger_tests` + `csrf_tests` (116 LoC, replaced by per-crate test suites), `security_monitor` placeholder (53 LoC, never implemented).

---

## [r281 cut] — 2026-04-24

### Security

#### At-rest encryption — full coverage of every column with user data
- **Actor memory encryption (Phase A + B)** — `actor_memory.value` plaintext column DROPPED. New `value_enc BYTEA NOT NULL` + `value_key_id UUID NOT NULL` (FK to `encryption_keys`). All writes flow through `talos_memory::register_memory_crypto_hook` — write without the hook registered panics by design. Migrations `20260423235406` (Phase A additive) + `20260424010000` (Phase B drop legacy column). Verifier: `cargo run --example verify_phase_b -p controller`.
- **Module-execution payload encryption** — new `input_data_enc` + `output_data_enc` + `trigger_metadata_enc` BYTEA columns + shared `payload_enc_key_id` UUID FK on `module_executions`. All writers (canonical `ModuleExecutionService`, engine `PostgresModuleExecutionStore`, webhook trigger handler) route through the shared `module_payload_encryption::encrypt_payload_bundle` helper — single source of truth for the wire format. Reader-side `ModuleRepository::with_encryption` transparently decrypts on `find_latest_completed_execution_io` + `list_completed_module_executions`. Migration `20260424030501`. Backfill tool: `cargo run --example backfill_module_payload_encryption`.
- **Workflow-execution output encryption (already shipped, now wired)** — backfilled 52 plaintext rows. Three writer paths (scheduler, ActorRepository::complete_execution, MCP mark_execution_completed) all route through encryption-aware methods. New `mark_execution_waiting` mirrors the `_completed` shape for in-flight workflows.

#### KEK → KMS migration (six phases shipped)
- **Pluggable KEK abstraction** — new `KekProvider` trait in `controller/src/secrets/kek_provider.rs`. `EnvKekProvider` (dev) wraps the existing AES-256-GCM logic. `VaultTransitProvider` (prod) calls Vault transit `/encrypt` + `/decrypt` over HTTPS — KEK never enters controller process memory. Selectable via `KEK_PROVIDER=env|vault`. Boot-time `health_check` runs a real encrypt+decrypt round-trip against Vault before publishing the provider; fail-closed on auth/network failure.
- **Dual-wrap migration (Phase 3)** — operator tool `cargo run --example rewrap_deks_to_vault` rewraps every DEK from env→Vault with verify-before-commit per row. Closes the irreversibility cliff: a target provider that silently corrupts on write is caught at row N, not at first decrypt-after-migration.
- **Reader cutover with fail-closed rollback (Phase 4)** — `decrypt_dek` cascades active-provider-first then legacy-provider-fallback. Rollback to env is a config flip, not a re-migration.
- **Terminal migration (Phase 5)** — `encrypted_key_v2` promoted to canonical `encrypted_key`, NOT NULL enforced. Pre-flight tool `verify_v2_decryptable` blocks the migration unless every row decrypts cleanly with the active provider.
- **Vault dev service** in `docker-compose.yml` with persistent `vault_data` volume — survives container restart so transit keys aren't wiped.

#### Per-actor LLM data-egress ceiling
- **`actors.max_llm_tier`** column (migration `20260424100000`) — `tier1` = local Ollama only (data must not leave host) / `tier2` = external providers allowed (default for backward compat).
- **HMAC-bound** in BOTH `JobRequest` AND `PipelineJobRequest` signing payloads (appended at end per the wire-format stability rule). On-wire attackers cannot downgrade tier-1 → tier-2 without invalidating the signature.
- **Five worker enforcement surfaces** — refused for tier-1 actors regardless of `allowed_hosts`/`allowed_secrets`: (1) `llm::*` host fns via `decide_llm_tier_access`, (2) `wit_http::fetch` + `fetch_all`, (3) `wit_graphql::execute`, (4) `wit_webhook::send`, (5) HTTP-stream. Plus `resolve_vault_header` refuses `vault://anthropic|openai|gemini/*` substitution. Reserved hosts: `api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com`, `aiplatform.googleapis.com` (with subdomain match).
- **Defense in depth** — `build_encrypted_secrets_for` skips LLM-provider key prefetch entirely for tier-1 jobs. Anthropic/OpenAI/Gemini keys never cross the wire (encrypted or otherwise) for sensitive actors.
- **Audit log** — every `set_actor_llm_tier_ceiling` call writes an `admin_event_log` entry with full `previous_tier → new_tier` transition. Append-only trigger means stealth-flip-exfiltrate-flip-back leaves a permanent record.
- **Single setter contract** — `ActorRepository::apply_actor_to_engine` is the canonical engine-stamping path. Returns `Result<()>`; fail-closes to Tier1 on DB error. All 10 controller call sites converted from bare `engine.set_actor_id`.
- **MCP tool** — `set_actor_llm_tier_ceiling(actor_id, tier)`.
- **Default Tier-1 model upgraded** — `mistral` (7B) → `qwen2.5:32b` in `Dockerfile.ollama`. `llama3.3:70b` documented as opt-in for 64GB+ hardware.

#### Supply chain hardening
- **`deny.toml`** — strict `cargo-deny` policy: RUSTSEC advisories, license allowlist (permissive OSI only), source allowlist (crates.io + in-tree paths only), banned-crate list. 11 current advisory exemptions, all documented with exploitability assessment + upstream-tracking link.
- **CI gating** — `cargo deny check` + `cargo audit` both block merge on violation in `.github/workflows/ci.yml`.
- **Digest-pinned Docker images** — every image in `docker-compose.yml` + `controller/Dockerfile` + `Dockerfile.ollama` pinned by SHA-256 digest. Tag re-push attacks structurally impossible.
- **Dependabot** — `.github/dependabot.yml` weekly bumps for cargo / Docker / docker-compose / GitHub Actions, grouped by domain (async-runtime, serde, database, observability, wasmtime, aws-sdk, crypto).

#### SLSA Level 2 release signing
- **Cosign keyless** image signing via Sigstore + Rekor in `.github/workflows/release.yml`. Identity bound to GitHub Actions OIDC token — no key custody.
- **SBOM** generated per image (syft → SPDX-JSON), attested via cosign as in-toto statement.
- **SLSA L3 provenance** via `slsa-framework/slsa-github-generator@v2.0.0` reusable workflow.
- **Verification surface** — `scripts/verify-image.sh` + `make verify-image IMAGE=...` + `make verify-all-images VERSION=...`. Fail-fast on any of: image signature, SBOM attestation, SLSA provenance.
- **Both `cosign-installer` and `sbom-action` pinned by full commit SHA** (not `@v3`) — these run with our OIDC token and a moving tag is the highest-leverage supply-chain vector.

#### Older items below

### Older Security (pre-2026-04-24)

- **CRITICAL**: Fix cross-tenant secret disclosure in `get_secrets_by_paths` — added `owner_user_id` filtering at all 7 call sites (secrets/mod.rs, sandbox.rs, parallel.rs)
- **HIGH**: Fix NATS subject injection via Redis-stored approval topics — validate topic format before publish at 2 sites (webhooks/mod.rs, executions.rs)
- **HIGH**: Fix mass assignment in `update_node_config` — strip `__` prefixed engine-internal keys, validate `skip_condition` length (graph.rs)
- **HIGH**: Add WASM content hash verification end-to-end — `expected_wasm_hash` in JobRequest/PipelineStep, worker verifies SHA-256 after loading (job-protocol, parallel.rs, worker/main.rs)
- **HIGH**: Atomic API key rotation — restructured `rotate_key` to use DB transaction (deactivate + insert in single commit)
- **HIGH**: Add audit logging for `delete_secret` — `RETURNING id` + async `secret_audit_log` INSERT
- **HIGH**: Worker NATS payload size cap — 32 MB check before `serde_json::from_slice` at both job/pipeline subscription sites
- **MEDIUM**: Fix 13 DB error message leakage sites — log `?e` server-side, return generic strings to clients (graph.rs, workflows.rs, advanced.rs, executions.rs, modules.rs, versions.rs, resources.rs)
- **MEDIUM**: Schema regex compilation DoS prevention — `RegexBuilder::size_limit(256KB)` + 500-char pattern length cap
- **MEDIUM**: LIKE metacharacter escaping in search — `escape_like()` function applied at 3 ILIKE pattern construction sites
- **MEDIUM**: TOTP replay prevention — Redis `SET NX EX 90` with fail-closed on unavailability
- **MEDIUM**: JWT issuer claim — `iss: "talos"` added to Claims, verified during validation
- **MEDIUM**: DLP pattern expansion — AWS ASIA temp credentials, database connection string redaction
- **MEDIUM**: Redis TLS enforcement — startup panic if `REDIS_URL` uses `redis://` in production
- **LOW**: Rhai expression length caps — `retry_condition`, `retry_delay_expression`, `skip_condition` limited to 2000 chars
- **LOW**: Node ID character allowlist — `[a-zA-Z0-9._-]` in `create_workflow` and `add_node_to_workflow`
- **LOW**: Graph cycle detection — `petgraph::is_cyclic_directed()` in `add_edge_to_workflow`
- **LOW**: Execution status observability — `tracing::warn!` when `mark_execution_completed/failed` affects 0 rows
- **LOW**: API key prefix comparison — constant-time via `subtle::ConstantTimeEq`
- Container image name validation in compilation container module

### Added

- **Execution output encryption at rest** — AES-256-GCM via existing DEK/KEK envelope encryption. New columns `output_data_enc` + `output_enc_key_id` on `workflow_executions`. Transparent encrypt-on-write / decrypt-on-read in `ExecutionRepository`. Migration `20260408170952`.
- **Compilation container isolation** — Podman-based sandbox for `cargo component build` with `--network=none --read-only --cap-drop=ALL --memory=2g --cpus=2`. `Dockerfile.builder`, `container.rs` module, `build-compiler-image.sh` script.
- **Per-node execution timing** — DB trigger `compute_execution_event_duration()` auto-computes `duration_ms` from `node_started` → `node_completed` pairs. Zero engine code changes. Migration `20260408171500`.
- **Execution waterfall visualization** — `ExecutionWaterfall.tsx` SVG component with horizontal bar chart. Timeline/Waterfall tab toggle in `ExecutionPanel.tsx`. Execution replay slider.
- **Python SDK** — `sdks/python/talos_sdk/` with `@talos_module` decorator, `TalosInput`/`TalosOutput` types, host function stubs, 3 examples. `compile_python_module()` in controller via `componentize-py`.
- **TypeScript SDK** — `sdks/typescript/` with `talosModule()` function, TypeScript types, `__TALOS_WORLD__` metadata export.
- **5 new agentic workflow templates**: `rag-pipeline`, `multi-agent-router`, `human-review-gate`, `pii-scrubber`, `webhook-to-slack`
- **Compliance documentation**: STRIDE threat model, security architecture, SOC 2 control mapping (40+ controls), pentest scope/preparation
- **SOC 2 evidence collection**: `scripts/soc2/collect-evidence.sh` (automated audit export), `scripts/soc2/verify-controls.sql` (control verification)
- **Managed cloud design document**: tenant isolation, per-tenant KEK, worker pools, billing metering, control plane API
- **CI security job**: GitHub Actions workflow with cargo audit, secret scanning, migration verification, container image build, SDK lint
- **Makefile targets**: `builder-image`, `verify-encryption`, `soc2-evidence`, `soc2-verify`, `backfill-encrypt`, `sdk-python-lint`, `sdk-ts-lint`
- Performance indexes for encrypted output columns

### Changed

- `ExecutionRepository::new()` now accepts optional `Arc<SecretsManager>` via `with_encryption()` constructor
- `ExecutionEvent` (both engine and repository structs) includes `duration_ms: Option<i64>` field
- GraphQL `ExecutionEvent` type exposes `durationMs` for waterfall visualization
