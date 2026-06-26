# Functional & governance audit — 2026-06-25

A live, end-to-end audit of a running Talos stack (`make up`), driven through the
real API surfaces (GraphQL, webhooks, scheduler, WS) rather than unit tests. The
goal was to exercise the data-plane and governance paths a real operator hits and
find correctness bugs that pass `cargo check` and the unit suite but break at
request time.

**Outcome: 14 real bugs found and fixed (all live-verified and merged); two
systemic bug *classes* identified, swept to exhaustion, and now **frozen with
structural lints** (checks 46/47, #272); a battle-hardening phase that closed an
actor-budget TOCTOU race (#284) and made 2 of 4 inert governance caps real
(#285–#288); and ~37 surfaces verified clean (including the full OAuth CSRF/state
boundary, the MCP untrusted-compile path, sub-workflow dispatch, the
loop/collect/capability-dispatch structural nodes, the LLM dispatch kinds on
tier-1 local Ollama, the judge/reflective-retry/agent-loop orchestration nodes,
the concurrency primitives, input-boundary + fail-open sweeps, and live dependency failure-injection (NATS/Redis/worker)).** This
doc captures the bugs, the two classes (and the lints that freeze them), and the
negative results (so they aren't re-investigated).

> Method note: every fix was verified against the running stack (trigger →
> observe DB/worker state), not just compiled. The full Rust test suite was
> **not** runnable locally during the audit (host-disk exhaustion); CI
> (`quality.yml`) is the suite gate. Several findings were reproduced with a
> hand-copied "Echo/Debug" module whose `content_hash` was deliberately
> tampered — a useful fault-injection, but note it is *not* a valid fixture for
> the WASM-integrity-checked paths (the integrity check correctly rejects it).

---

## The two systemic classes (freeze these)

### Class A — execution tracking rows created but never finalized

**Invariant:** every dispatch path that INSERTs a row into `workflow_executions`
or `module_executions` with a non-terminal status (`queued`/`running`/`pending`)
MUST guarantee that the same logical operation later transitions it to a terminal
status (`completed`/`failed`/`cancelled`) — and the create MUST be ordered-before
(awaited, not raced-with) the finalizer.

Five bugs, each a different way to violate it (plus the freeze + a sibling fix it surfaced):

| PR | Path | Violation |
|----|------|-----------|
| #261 | GraphQL `trigger_workflow` | created `queued`, never promoted to `running`; the `running`-guarded `mark_execution_completed` then no-op'd → stuck `queued` |
| #263 | engine pipeline dispatch | wrote a **node id** into `module_executions.module_id` (FK violation) → per-step tracking dropped |
| #267 | webhook-fired module | INSERTed `module_executions` `running`, **never finalized** (inline request/reply, no result subscriber) |
| #268 | workflow-chain dispatch | the `'running'` INSERT ran in a fire-and-forget `tokio::spawn`, **racing** the inline fast-fail finalizer; finalizer won the race → orphaned `running` |
| #271 | crash-recovery resume | claimed `running → resuming` and re-ran the graph, but `resume_one` never finalized (assumed the engine did) **and** the finalizers were guarded `WHERE status='running'` (don't match `resuming`) → stuck `resuming` forever |
| #272 | freeze + sibling fix | added check 46 to freeze the class; it immediately surfaced that #271 only widened `talos-workflow-repository` — so widened `talos-execution-repository`'s sibling finalizers too |
| (n/a) | scheduler, actor-handoff, retry, replay | **audited — clean**: all *await* the create/transition-to-`running` before spawning the run, and finalize both arms |

**Why the unit suite missed all five:** the MCP / `ExecutionOrchestrationService`
path creates rows as `running` (not `queued`) and finalizes synchronously, so
MCP-driven tests pass. The bugs lived only on the GraphQL/webhook/chain dispatch
paths.

**Structural lint — implemented (check 46, #272):** flags any single-line
`WHERE id = $N AND status = 'running'` finalizer guard in the execution-status
repos (it must be `status IN ('running','resuming')` so a crash-recovery-claimed
row can finalize — the #271 shape). Opt-out: `// allow-running-only-finalize`.
The broader sub-shapes — an `INSERT` with no finalizer at all (#267) and a
spawned `INSERT` racing an inline finalizer (#268) — resist a precise static
grep, so they're guarded by this doc + code review rather than lint; the
audited-clean callers above are the reference pattern.

### Class B — append-only audit tables FK-bound to deletable parents

**Invariant:** a table carrying the `prevent_audit_modification` trigger
(`BEFORE DELETE OR UPDATE`) MUST NOT have an incoming FK from a deletable parent
with `ON DELETE CASCADE` or `ON DELETE SET NULL` — both fire a DELETE/UPDATE on
the immutable audit row and abort the parent's deletion. Audit rows should hold
the parent id as a plain (nullable) historical reference, not an enforced FK.

| PR | Audit table | Was | Effect |
|----|-------------|-----|--------|
| #264 | `secret_audit_log` → `secrets` | `ON DELETE CASCADE` | `deleteSecret` could **never** succeed (every secret has ≥1 audit row) |
| #266 | `auth_audit_log` / `admin_event_log` → `users` | `ON DELETE SET NULL` | user deletion blocked (SET-NULL is an UPDATE, also trigger-blocked) — latent (no delete-user API yet) |
| (n/a) | `audit_events` | no such FK | clean |

**Structural lint — implemented (check 47, #272):** scans migrations newer than
the last fix for a `CREATE`/`ALTER` of an append-only audit table that adds
`ON DELETE CASCADE | SET NULL`. Pre-fix history is grandfathered by timestamp
(the bad FKs are dropped by `20260625140000`/`150000`), so no false positives on
immutable migrations. The four audit tables are a closed set; a new one → add it
to the check's `AUDIT_TABLES`.

---

## Bug-by-bug

1. **#261 — GraphQL-triggered workflows never reach `completed`.** `trigger_workflow`
   created the execution `queued` and spawned dispatch, but never promoted
   `queued → running`; the success-path `mark_execution_completed` is guarded
   `WHERE status='running'`, so it silently matched zero rows. *Zero executions
   had ever completed on a fresh deploy.* Fixed by promoting via
   `mark_execution_running_from_queued` in the spawned task before the engine runs.

2. **#263 — pipeline step tracking FK violation.** `engine_dispatch_pipeline`
   passed the graph **node id** to `record_started` (the store's `resolve_module_id`
   is an identity fn), so a node id was inserted into `module_executions.module_id`
   → FK violation, per-step tracking/analytics dropped for *all* multi-node runs.
   Fixed by using the already-resolved `chain_module_ids[i]`.

3. **#264 — secrets can't be deleted.** `secret_audit_log.secret_id` was
   `ON DELETE CASCADE`, blocked by the audit-immutability trigger. Dropped the FK.

4. **#265 — semantic memory completely broken on default deploy.** The embedding
   columns were `vector(1024)` (resized for Voyage) but the dev compose still
   defaulted to `nomic-embed-text` (768-dim) → every semantic write failed
   pgvector's dimension check. Aligned the dev default to `mxbai-embed-large`
   (1024-dim, local).

5. **#266 — user deletion blocked by audit FKs** (Class B sibling of #264). Latent.

6. **#267 — webhook-fired module executions stuck `running`.** No finalizer on the
   webhook's inline request/reply path. Fixed with
   `complete/fail_execution_from_worker` after the result match.

7. **#268 — chained workflow executions orphaned `running` on trigger error.** A
   race between the fire-and-forget `'running'` INSERT and the inline fast-fail
   finalizer. Fixed by making the fast-fail finalizers race-safe upserts.

8. **#269 — module-level approval gates unusable.** The approval gate stored the
   **execution id** in `execution_approvals.workflow_id` ("the real workflow_id is
   not always threaded through at this call site"), so `approve_execution`'s
   ownership join (`workflows.id = execution_approvals.workflow_id`) never matched
   → every approval returned "not found" → the protected module could never run.
   Fixed by resolving the real `workflow_id` from the in-flight execution row.

9. **#271 — crash-recovered executions stuck `resuming`.** With
   `EXECUTION_CHECKPOINTING_ENABLED` on (durable execution, off by default), the
   startup recovery sweep claimed orphaned `running` rows (`running → resuming`)
   and re-ran the graph, but nothing finalized them: `resume_one`'s Ok arm
   assumed the engine writes the terminal status (no run path does — every other
   caller finalizes afterward), **and** the finalizers were guarded
   `WHERE status='running'` (don't match `resuming`). So a resumed run executed
   but stuck in `resuming` forever. Fixed both halves: `resume_one` now finalizes
   from `ctx` (`mark_execution_completed`, or `mark_execution_waiting` when
   `ctx.waiting`), and the finalizers accept `status IN ('running','resuming')`.
   Opt-in feature, but broke resume completion entirely when enabled.

10. **#275 — `compile_custom_sandbox` pointed callers at a dead execution path.**
    The MCP tool's success message told the caller to run the freshly-compiled
    module via a `sandbox_<short_id>-v1` tool that can never resolve: the
    `short_id` comes from a throwaway `Uuid::new_v4()` that's never persisted
    (the module is stored in the unified `modules` table under a *separate*
    `module_id`, returned as "Template ID"); user-compiled sandboxes aren't
    registered in `tools/list` at all (only catalog templates are); and the
    generic `*-v1` dispatcher routes every such call to
    `install_module_from_catalog`, whose slug lookup fails with
    `"Module 'sandbox-<short_id>' not found in catalog"`. An MCP agent following
    the tool's own guidance hit a wall. Reproduced live, then repointed the
    message at the two paths that actually work (`module_id` in a workflow, or
    `test_module(module_id)` for a direct one-shot — both verified executing).

11. **#277 — `create_workflow` accepted multi-node cycles.** The plain
    authoring path only rejected the trivial self-edge (`n -> n`) via
    `validate_edge_targets`; a multi-node cycle (`a -> b -> a`) passed and was
    persisted. The engine requires a DAG and fails such a run at trigger time
    with "workflow graph contains a cycle" — so the workflow was created
    successfully but unexecutable. Both the `add_edge` and
    `create_workflow_from_description` paths already gated on
    `petgraph::is_cyclic_directed`; the plain path was the gap. Fixed with a
    pure-Rust `validate_acyclic` helper (iterative three-colour DFS, 7 unit
    tests) over the full edge set. Verified live: self-loop + 2-/3-node cycles
    rejected, linear + diamond DAGs still accepted.

12. **#278 — concurrent compiles cross-contaminated WASM artifacts.** Two
    `compile_custom_sandbox` calls running concurrently could persist module B
    with module A's compiled WASM (its stored `content_hash` no longer matching
    its own source). Root cause: all compiles share one `CARGO_TARGET_DIR` (to
    keep the dependency cache warm) AND every sandbox compile uses a *fixed*
    cargo package name (`custom_sandbox`), so the artifact is always
    `custom_sandbox.wasm`; concurrent builds clobber that one file and the
    mtime-based read hands both jobs whichever finished last. Found while
    testing sub-workflow dispatch — two judge modules compiled in parallel came
    out byte-identical; compiling either alone was correct. It also silently
    corrupted the `node_result_cache` (keyed on `module_hash`). Fixed by folding
    the unique per-call `job_id` into the cargo package name in
    `create_workspace`, isolating each build's artifact while preserving the
    shared dependency cache. Verified live: parallel compiles now yield distinct
    `content_hash`es.

13. **#281 — fresh `make up` baked a 768-dim embedder against 1024-dim runtime**
    (completes #265). #265 fixed the *runtime* embedding config
    (`EMBEDDING_MODEL=mxbai-embed-large`, `EMBEDDING_DIMENSIONS=1024`) but left
    the docker-compose `EMBED_MODEL` *build-arg* default at `nomic-embed-text`
    (768-dim), overriding `Dockerfile.ollama`'s own `mxbai` default. Since
    `ollama_data` is a named volume seeded from the baked image, a fresh clone
    baked a 768-dim embedder while the controller requests
    `mxbai-embed-large` (1024) → every semantic / actor-memory write fails
    (model-not-present on the OpenAI-compat embeddings endpoint, or pgvector's
    dimension check). Same dimension-mismatch class as #265, surviving on the
    bake side. Fixed the compose default to `mxbai-embed-large` so baked model +
    runtime model + dimensions + column dim are all 1024 in lockstep. Found while
    wiring up local Ollama to test the LLM dispatch kinds.

14. **#284 — actor execution-budget TOCTOU (governance/cost-control bypass).**
    `max_executions_per_hour` / `_total` were enforced check-then-act:
    `authorize_workflow_trigger` `COUNT`s recent executions, but the execution
    INSERT happens separately with no lock spanning both. Under concurrent
    triggers every request reads `count < cap` before any INSERT commits, so they
    all pass. Reproduced live: a `max_executions_per_hour=2` actor admitted **10**
    (up to 19) under a barrier-synchronised 20-way fire. The workflow
    concurrency-limit path already serialised with `SELECT … FOR UPDATE`; the
    actor-budget path had no equivalent. Fixed by re-checking the budget *inside*
    `create_execution_under_concurrency_limit` under a per-actor
    `pg_advisory_xact_lock` (atomic with the INSERT). Post-fix: exactly 2 of 25
    admitted. *(Shell `&` concurrency didn't expose it — the barrier harness did;
    a reminder that TOCTOU repro needs true window alignment.)*

Plus **#262** — restored four onboarding fixes (`/auth/csrf` dev proxy, catalog
seeding default, self-loop edge guard, frontend port docs) dropped by #259's
squash merge.

---

## Battle-hardening phase — actor-budget enforcement

After #284 fixed the budget *race*, a sibling-hunt found a second class: **four
actor budget dimensions were stored, settable, returned, and documented as
"platform safety caps with implicit defaults" — but enforced nowhere** (operators
relied on phantom protection). The enforceable ones were made real; the rest
honestly relabelled.

| PR | Cap | Outcome |
|----|-----|---------|
| #285 | (all four) | relabelled **RESERVED — NOT YET ENFORCED** (honesty; zero behaviour change) |
| #286 | `max_workflows_per_minute` | **enforced** — atomic per-actor trigger-rate cap in the same advisory-lock block; verified cap=3 → exactly 3 of 15 concurrent |
| #287 | `max_fuel_per_hour` | **enforced** — rolling per-hour `SUM(fuel_consumed)` from `execution_cost_rollup`; verified blocked after the hourly fuel was burned. (`::bigint` cast needed — Postgres `SUM(bigint)`→`numeric` errored every trigger until caught live) |
| #288 | `max_compilations_per_hour`, `max_outbound_requests_per_hour`, `max_fuel_per_execution` | **documented unenforceable as per-actor caps** — compiles/outbound aren't actor-attributed (no row to gate on); would need attribution + tracking, or reframing per-user/agent |

Net: 4 of 7 budget dimensions now genuinely enforced (atomic, race-safe); the
rest accurately labelled.

## Open follow-ups (noted, not yet fixed)

- **Module-approval status semantics** *(investigated 2026-06-26 — NOT a safe
  quick fix; needs a scoped design task).* The module-level `requires_approval_for`
  path (engine_dispatch_single/pipeline) returns a plain `Err("Execution paused…")`
  on `ApprovalStatus::Pending`, so the run loop fails the node → execution
  `failed`; recovery is *fail → approve → retry*. The confidence-gate path
  (`engine.rs`) instead returns an `Err(json!({"__waiting__": true, …}))` envelope
  that the run loop maps to `ctx.waiting → mark_execution_waiting`, and resume is
  driven by a **separate suspension/continuation subsystem**
  (`talos-continuation-trigger::trigger_continuation_workflow` dispatches a
  continuation workflow when the gate is satisfied) — NOT a checkpoint restore.
  So the two are different subsystems, and `failed`→retry is the *deliberate*
  no-suspension design. **Do not naively flip module-approval to `waiting`:** a
  `waiting` row with no suspension/continuation hook never resumes (and crash
  recovery, which loads `status='waiting'`, would mishandle it) — strictly worse
  than the cosmetic `failed` status. A proper fix routes module-approval through
  the suspension/continuation machinery (emit `__waiting__`, register a
  suspension, wire the approve→continuation resume), or — lower-risk — adds an
  `error_type`/marker column (migration) so dashboards can filter
  "pending approval" from genuine failures without touching resume semantics.
  **Interim mitigation shipped:** both module-approval pending messages now carry
  a stable `[APPROVAL_PENDING]` prefix, so alerting can exclude them
  (`error_message NOT LIKE '[APPROVAL_PENDING]%'`) without a schema or
  resume-semantics change. The full suspend/continuation reconcile remains the
  proper (scoped) fix.
- ~~**Webhook FK-routing log noise.**~~ **RESOLVED.** The WASM-log handler
  routed `workflow_execution_logs` vs `module_execution_logs` by attempting the
  workflow insert and catching the FK violation — which Postgres logged as an
  `ERROR` per standalone-module log. `add_workflow_log` now does a
  `WHERE EXISTS (… workflow_executions …)`-guarded insert and returns
  `Ok(false)` (a clean 0-row no-op) for a non-workflow id, so the subscriber
  routes to the module-log table on the boolean instead of on an FK error. No
  Postgres ERROR, single round trip for the common case; genuine failures (the
  5000-entry rate-limit trigger, DB outage) still surface as `Err` so a real
  workflow log isn't misrouted. DB-verified: guarded insert is `INSERT 0 0` for
  a fake id (no error) vs `INSERT 0 1` for a real one.
- **Budget USD cap is inert.** `check_execution_allowed` enforces actor status +
  per-hour rate at trigger time, but the lifetime-USD cap depends on consumption
  tracking that is documented as *"Always 0 until budget tracking is wired."*
  Expected/incomplete, not a bug — but the schema exposes `total_budget_usd` as if
  enforced.

---

## Verified clean (negative results — don't re-investigate)

- **Class A remainder:** scheduler, actor-handoff, retry, replay all finalize
  correctly (await create-to-`running` before spawning the run). Crash-recovery
  resume did **not** — that was #271 (above); after the fix, verified live
  (orphan → `resuming` → `completed`).
- **Class B remainder:** `audit_events` has no cascade/set-null FK.
- **Cross-tenant isolation (RLS):** a second user was denied on every vector —
  reading/triggering another user's workflow, listing their secrets/actors,
  reading their execution history, and *using their private module* (user-scoped
  module resolution → "module not found") — while retaining access to its own.
  Enforced at the **application layer** (every query/mutation gates on
  `user_id`/org membership); the DB RLS `SET ROLE` backstop is documented as
  not-yet-active, so those app-layer gates are currently the sole line — they
  held on every path tried.
- **Capability-ceiling lattice gate:** rejects over-ceiling modules
  (`database-node` vs `minimal-node`, clear actionable error) and allows
  within-ceiling, stamping `actor_id`. Reads each module's *stored*
  `capability_world` (not the node's self-declared one).
- **DLP redaction:** GitHub PAT, AWS key, and Anthropic-key shapes all redacted
  to `[REDACTED:…]` in stored execution events; execution output is also encrypted
  at rest (`output_data_enc`).
- **Secrets read surface:** the GraphQL `Secret` type exposes no `value` field;
  querying `value` is a schema error.
- **Worker execution path:** signed-NATS dispatch → WASM sandbox → result, single-
  and multi-node, verified completing.
- **Other surfaces exercised working:** signup/login/session, CSRF seeding,
  template catalog seeding, catalog module install/compile (source → WASM),
  WebSocket transport handshake (101 + auth/origin).
- **OAuth security boundary (no-creds audit):** the entire OAuth CSRF/state
  surface is exercisable without real provider credentials because state
  validation runs *before* the provider code exchange
  (`talos-oauth::handle_callback` → `validate_state_token` → provider call).
  All paths verified clean against the running stack:
  - *Login init* — invalid provider → 400; unconfigured provider (google/okta/
    snyk) → 500 with the generic "OAuth login unavailable" message, **no
    config-state leak** (MCP-995).
  - *Callback* — invalid provider → 400; missing `code` → `?error=missing_code`;
    provider-supplied error with a `<script>` payload → sanitized to
    `oauth_error` (MCP-1094); missing `state` and forged `state` → both
    `csrf_mismatch`.
  - *Open-redirect* — `next` / `redirect_uri` / `state=//evil.com` request
    params cannot move the post-callback redirect off the validated frontend
    host; target comes from `get_frontend_url()` server-side config, not request
    input (MCP-623 / MCP-1000).
  - *Session-binding (#249 login-CSRF)* — for a state row written with a
    `session_binding_hash`: a callback with **no** binding cookie is rejected
    (`missing session-binding cookie` warn), a **wrong** cookie is rejected
    (`session-binding mismatch` warn, constant-time compare), and the **correct**
    cookie passes the gate. Critically, the token is consumed *before* the
    binding check fails — every tested row ended `used=true`, so a failed
    binding check still burns the `state` and denies an attacker any retry.
    (Method note: the Redis replay layer also bit the test itself — reusing one
    `state` across the three cases let the first consume the Redis nonce and
    short-circuit the other two at replay-detection; distinct tokens per case
    were required. That's the replay defense working as intended.)
  - *Integration callbacks* (gmail/slack/atlassian, separate `/api/*/callback`
    routes) — missing/forged params produce a graceful `*_error=` redirect to
    the validated frontend host with a generic "Failed to connect" message, no
    internal-detail leak.
  - **Not covered (credential-gated):** the happy path *past* the CSRF gate —
    real provider token exchange → user create/link → session issuance —
    requires a registered provider OAuth app + `*_CLIENT_ID`/`*_CLIENT_SECRET`
    in env. See `docs/OAUTH_SETUP.md`.
- **MCP server / untrusted-compile path.** Driven end-to-end through the real
  JSON-RPC `/mcp` endpoint. Auth chain: GraphQL signup → admin API key →
  `register_mcp_agent` → agent Bearer token (a *separate* `mcp_agents` identity,
  not the GraphQL `X-API-Key`). All paths below verified against the running
  stack; the one bug found is #275 above.
  - *Auth* — `/mcp` with no token → 401; agent Bearer token authenticates; 376
    tools enumerated.
  - *Valid compile* — `compile_custom_sandbox` (minimal-node) compiles real Rust
    → WASM and persists to the unified `modules` table (owned by the caller,
    content-hashed, ~106 KB), runnable.
  - *Dependency allowlist* — disallowed crate (`reqwest`), wildcard version
    (`serde = "*"`), and wrong-shape `dependencies` (string instead of object,
    MCP-307) all rejected before the build, with clear messages.
  - *Capability gating* — invalid `capability_world` rejected; the per-role
    ceiling is enforced (the rejection surfaces the role's allowed capability
    set).
  - *Runtime* — `run_sandbox` (inline compile + execute) and
    `test_module(module_id)` (execute a *stored* module) both run with fuel
    accounting (`__fuel_consumed__`).
  - *Persistence* — compiled sandboxes land in `modules` (Phase-5.1 unified the
    legacy `node_templates` / `wasm_modules` tables away); the returned
    "Template ID" is `modules.id` and drives both the workflow and `test_module`
    paths.
- **Sub-workflow dispatch.** The dispatcher machinery
  (`execute_subworkflow_graph` → `collapse_subworkflow_output` →
  per-contract interpretation) is sound — the one bug in this area was the
  compile-concurrency issue (#278), which *masked* itself here (two judge
  sub-workflows compiled in parallel returned the same verdict because they
  shared WASM). With that fixed, every path verified live via
  `test_subworkflow_contract` + a full parent run:
  - *judge* — single-terminal collapse + `JudgeVerdict::from_collapsed`: a valid
    `{score,passed,reasoning,feedback}` parses with `malformed_fields=0`; a
    verdict missing `passed`+`feedback` parses with `malformed_fields=2`
    (defaults applied, surfaced loudly).
  - *classifier* — extracts the class string (`classifier_class="urgent"`),
    `passed=true`.
  - *subworkflow* / *reflection* — pass when there's no `__error` envelope.
  - *collapse* — single terminal → its unwrapped output; **multiple terminals →
    label-keyed map** (`{leftnode:{…}, rightnode:{…}}`), the documented diamond
    fallback.
  - *parent → sub_workflow* — a parent with an `add_sub_workflow_node` node runs
    the child end-to-end; output flows back keyed by the node label
    (`{"sw":{"fib":34}}`), status `completed`.
  - *Not covered (LLM-gated):* `ensemble` and `llm_dispatch` need a live LLM
    provider for the synthesis/judge step (no key configured); `test_subworkflow_contract`
    doesn't expose those contracts.
- **Structural execution nodes** (loop / collect / capability_dispatch). Built
  each with the graph-mutation tools and ran the parent end-to-end:
  - *loop* — re-dispatches a body node while a Rhai condition holds, capped by
    `max_iterations`. `count < 3` → 3 iterations, `termination_reason:
    condition_false`; `true` with max 5 → 5 iterations, `max_iterations` (the
    infinite-loop guard fires); `false` → 1 iteration (body runs once, condition
    checked after).
  - *collect* — fan-in from two branches gathers `{items: [...], count: N}`
    (per-item `__fuel_consumed__` envelope stripped).
  - *capability_dispatch* — match → routes to the best capability-tagged
    workflow and runs it, stamping `__dispatched_workflow_id__` /
    `__matched_capabilities` on the output; no match + no `fallback_workflow_id`
    → fail-closed (`status: failed`, null output), not a hang or silent pass.
- **`add_node_to_workflow` inline-Rust path** (`InlineCompileService`). Adding a
  node with `rust_code` compiles + persists a per-node module and wires it in
  one call; verified end-to-end (a doubling module compiled, persisted, and ran
  → `doubled=14`). Shares the `create_workspace` chokepoint, so the #278
  concurrency fix covers it. Same security gates as `compile_custom_sandbox`,
  confirmed live: disallowed dependency rejected; a type error returns a clean
  **pre-compile lint** error (skips the ~30–60 s doomed compile); invalid
  `capability_world` rejected with the valid-values list.
- **LLM dispatch kinds (tier-1 local Ollama).** After fixing the embedder bake
  (#281), pulled `llama3.2:1b` into the dev Ollama and exercised the LLM paths
  with **no external API key** (tier-1, data stays on-host):
  - *direct `llm::complete`* — an `agent-node` module calling
    `talos::core::llm::complete` with `provider: ollama, model: llama3.2:1b`
    runs real inference: "What is 2+2?" → "4", `completed`.
  - *ensemble* — `add_ensemble_node` over the chat workflow ×3 with
    `majority_vote` consensus → "Paris.", output stamped `__ensemble_method__` /
    `__ensemble_size__`. (Consensus is validated: `majority`→ rejected, only
    `majority_vote` / `best_of_n` / `first_pass` accepted.)
  - *llm_dispatch* — an LLM classifier workflow returns `{class}`; the dispatch
    routes to the matching route workflow and runs it, stamping
    `__dispatched_class__` / `__dispatched_workflow_id__` ("Capital of Japan?" →
    "Tokyo." via the `general` route). Routing is faithful to whatever class the
    classifier returns (the 1b model's occasional misclassification is model
    quality, not a dispatch bug).
  - *Note:* `judge`/`reflection` with a real LLM is covered by composition — the
    LLM module returns the verdict JSON and the judge contract parse +
    single-terminal collapse are already verified above.
- **LLM-orchestration nodes** (judge / reflective_retry / agent_loop). Built each
  with its graph-mutation tool and ran the parent end-to-end (tier-1 Ollama):
  - *judge node* — gates on `pass_threshold` against a judge workflow's verdict:
    score 0.9 vs threshold 0.5 → pass (stamps `__judge_score__` /
    `__judge_passed__` and passes the upstream output through); 0.9 vs 0.95 →
    fail (`on_failure: error` → `__error` → execution `failed`).
  - *reflective_retry* — child that always fails with `max_retries: 2` → runs the
    attempts, invokes the reflection workflow between them, and on exhaustion
    fails with a clear "Reflective retry exhausted 2 attempts. Last error: …"
    message (no hang, no silent pass).
  - *agent_loop* — a real-LLM body workflow with `max_iterations: 2` → ran 2
    iterations, accumulated `__agent_history__` (2 entries), capped at the limit
    (`finished: false`, `iterations: 2`), `final_output` carried the LLM answer.
- **Concurrency primitives** (battle-hardening sweep). Every contended path other
  than the actor budget (#284) was already serialised correctly:
  - *workflow concurrency limit* — `SELECT max_concurrent_executions … FOR UPDATE`
    on the workflow row (check-and-insert atomic).
  - *webhook duplicate-delivery dedup* — `talos_idempotency`'s `is_duplicate` is
    an atomic Redis `SET … NX EX` claim; concurrent identical deliveries → one
    wins. Race-safe by construction.
  - *approval submit* — `UPDATE … WHERE status='pending'` + `rows_affected`; the
    inline NATS reply-topic is consumed once. Double-submit can't double-resume.
  - *crash-recovery claim* — `FOR UPDATE SKIP LOCKED` (exactly-once across
    replicas).
- **Input-boundary fuzzing** (no crashes / no internal-detail 500s / no
  silent-accept-of-invalid). `create_workflow`: 100 KB name → "max 200 chars";
  5000 nodes → "exceeds 500 node limit"; `\x01` / `\0` in name → rejected;
  `NaN` / `Infinity` in numeric fields → rejected at JSON parse (400);
  negative/huge/`1e18` timeout → range-rejected; wrong-type `nodes` → rejected;
  empty name → rejected. `trigger_workflow` input: 200-level nesting and
  `Infinity` rejected at parse (never reach the `MAX_CANONICAL_DEPTH=128` signing
  guard); 100 K-element arrays / 500 KB strings complete or fail gracefully at the
  worker input limit; bare-array / bare-string / huge-int inputs accepted and run.
- **Fail-open hunt** (dependency-error → permissive-default class, MCP-366/535/999
  lineage). Grepped the gate/auth/budget/dedup/rate-limit crates for
  `.unwrap_or(false|None|0|true)` on dependency results — no live instances; the
  only hits are display-count defaults and a correct in-memory circuit-breaker
  default. The class is held by lint check 10 + the prior fix history. The new
  #286/#287 gates are fail-closed (the in-tx `COUNT`/`SUM` errors propagate via
  `?`, rolling back the create).
- **Dependency failure-injection** (live: stop a service mid-operation, observe,
  restart, confirm recovery). All three degrade gracefully / fail-closed — no
  stuck rows, no crash, no fail-open:
  - *NATS down → trigger* — the execution row is created `running`, the NATS
    client buffers the publish, and the run **completes ~10 s later when NATS
    returns** (the `wait_ms` window just expires first). No stuck row; resilient
    reconnect.
  - *Redis down* — `/live` `/ready` `/health` all stay 200 (Redis degraded is
    non-fatal by design; `/ready` 503s only on Postgres loss), and core triggers
    still **complete** (Redis isn't on the execution critical path). Clean
    recovery on restart.
  - *Worker down → trigger* — the execution finalizes **`failed`** on the
    dispatch timeout (NOT a stuck `running` — the Class A finalization invariant
    holding under dependency failure). No leak.
  - Full stack recovered after all three; end-to-end control trigger COMPLETED.
