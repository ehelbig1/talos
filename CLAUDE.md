# Talos Development Guidelines

## Build & Test Commands
```bash
make up-dev          # Start all services
make lint            # Lint Rust + frontend
make coverage        # Run tests with coverage
cargo check --workspace  # Quick Rust compilation check
cd frontend && npx vitest run  # Frontend unit tests
```

## Architecture
- **controller/** - Rust/Axum API server (GraphQL + REST). Owns Postgres + Neo4j credentials. Hosts NATS-RPC subscribers for memory / graph / database / state ops.
- **worker/** - Rust WASM runtime (wasmtime-based). **Credential-free**: no Postgres connection, no embedding-provider keys, no Neo4j. All data-plane access goes through signed NATS-RPC to the controller. The runtime library (runtime.rs, context.rs, host/, module_fetcher, sql_validator, wit_inspector, …) was extracted to **talos-worker-runtime/** in July 2026 — `worker/` is now the thin deployable bin (main.rs + self_register + metrics_server + secret_claim) with `worker/src/lib.rs` as a re-export shim, so controller-side consumers depend on the library crate, not the binary; historical `worker/src/host_impl.rs`-style paths in these docs refer to `talos-worker-runtime/src/*`.
- **frontend/** - React/TypeScript visual workflow editor.
- **talos-workflow-engine/**, **talos-workflow-engine-core/**, **talos-workflow-engine-nats/**, **talos-workflow-engine-test-utils/**, **talos-workflow-job-protocol/** - Workflow executor + trait boundaries + signed-NATS job/pipeline message types. Folded back into this workspace in May-2026 from the sibling `../talos-workflow-engine/` repo to simplify releases (one workspace, one `cargo check`, no `additional_contexts` indirection in image builds). Controller depends on `talos-workflow-engine-core`, `talos-workflow-engine`, `talos-workflow-engine-nats`; both controller and worker depend on `talos-workflow-job-protocol`. The engine's `SCHEMA_DOC` constant pulls from `docs/workflow-engine/graph-json-schema.md`.
- **talos-memory/** - Shared crate: canonical actor-memory service (writes, reads, semantic search, embedding LRU + thundering-herd dedupe), plus the four signed RPC protocols (`memory_rpc`, `graph_rpc`, `database_rpc`, `state_rpc`) and `rpc_auth` (HMAC + nonce replay cache + freshness window + canonical-bytes signing).
- **talos-secrets/**, **talos-dlp/**, **talos_sdk_macros/** - Other shared crates.
- **migrations/** - PostgreSQL migrations (sqlx).

## RPC layer (worker → controller)

Every cross-process data call uses the same signed-NATS-RPC pattern:

| Subject | Protocol | Sub | Notes |
|---|---|---|---|
| `talos.memory.op` | `memory_rpc::MemoryOp` (Get/Set/Delete/ListKeys/Search) | request/reply, in-flight cap 16 | All actor_memory access |
| `talos.graph.search` | `graph_rpc::GraphSearchRequest` | request/reply, cap 8 | Neo4j graph-RAG |
| `talos.database.query` | `database_rpc::DatabaseRpcRequest` | request/reply, cap 8 | Sandbox SQL via `database` WIT |
| `talos.state.write` | `state_rpc::StateWriteRequest` | fire-and-forget, cap 32 | `execution_state` durability |
| `talos.ml.predict` | `ml_rpc::MlPredictRequest` (batch ≤32 inputs) | request/reply, cap 8 | RFC 0011 model inference via `model` WIT; tenancy from the SIGNED user_id |
| `talos.ml.fewshot` | `ml_rpc::MlFewShotRequest` (k ≤8) | request/reply, cap 8 | Human-correction few-shot anchors for the LLM teacher leg (`model::few-shot` WIT); correction-only, class-balanced, features truncated to 512 B; tenancy from the SIGNED user_id; NO promoted-version requirement (the teacher loop matters most pre-promotion) |

**Before adding a new signed-RPC primitive**, walk `docs/platform-primitive-checklist.md` end-to-end. It captures the ten individual defense-in-depth and correctness fixes made across six review passes on integration_state (2026-04-15) so the next primitive doesn't repeat them. Pattern-copying from `memory_rpc` is NOT a substitute — several of the fixes were on issues that exist in `memory_rpc` too (e.g. zombie semaphore permits under DB outage, `tokio::spawn` orphaning on shutdown).

**Before adding ANY integration** (OAuth provider, third-party API, push source), read `docs/adding-an-integration.md` — the single authoritative guide + checklist. It names the correct-by-default toolkit (`talos_http_utils::trusted_client` for fixed hosts, `talos_http_body::read_json_capped` for bodies, `talos_oauth::OAuthIntegration` + `authorization_url`/`handle_oauth_callback` drivers for the OAuth flow, `OAuthCredentialService` for user-scoped tokens, `integration_state` for per-user watch state) and the non-negotiable tenancy/secret/SSRF/perf rules, cross-referenced to the lint checks (31/37/40/41/49) that enforce them. `talos-slack` is the canonical `OAuthIntegration` reference impl.

**Before adding a new push-notification integration** (watch channels / webhooks / Pub/Sub push on top of `integration_state`), walk `docs/integration-pattern.md` end-to-end. It distills the ten-file shape we converged on across `google_calendar` (first) and `gmail` (second) — what goes where, which helpers to reuse (`RenewalFailure`, `looks_like_oauth_failure`), and the pitfalls each reference implementation paid for. The third integration should be significantly faster than the second; reaching that only happens if the doc is consulted before coding, not after.

Efficient flow for Claude Code specifically: (a) spawn an **Explore** subagent in parallel against `controller/src/google_calendar/` and `controller/src/gmail/` to survey the two reference implementations; (b) spawn a **Plan** subagent to lay out the 10-file sequence; (c) implement file-by-file with green tests between pieces; (d) send the webhook-auth and renewal-path layers to a **code review** subagent before declaring done — those two are the highest-blast-radius parts of the pattern.

**Security invariants** (enforced by `talos_memory::rpc_auth` and the per-RPC `verify()` methods):
- HMAC-SHA256 signature bound to `(subject, actor_id, nonce, body)`
- Two-generation rotating nonce cache via `ArcSwap<DashMap>` — atomic O(1) rotation, no replay within `PAST_WINDOW_MS` (60 s)
- Asymmetric freshness window: 60 s past tolerance, 5 s future tolerance
- Constant-time MAC compare (`subtle::ConstantTimeEq`)
- Exact-wire-bytes signing via `RawSigned<T>` for Value-bearing ops (`MemoryOp::Set`, `IntegrationOp::Set` — the whole op is wrapped, so `value`/`metadata`/`ttl_hours`/`min_score` are all bound as the literal wire text, never re-derived); fixed-tag LE concat for scalar ops. This replaced the old `canonical_json_bytes` sorted-key re-serialisation, which hit serde_json's non-idempotent f64 round trip and made honest sender/receiver disagree (#598, the memory-RPC twin of job-protocol's `SignedJson`). **`RawSigned<T>` has ONE home: `talos_workflow_job_protocol`** — `talos_memory::rpc_auth::RawSigned` is a `pub use` of it, and `SignedJson` is the `pub type SignedJson = RawSigned<serde_json::Value>` alias (with `value()`/`into_value()` as the Value-flavoured spellings of `get()`/`into_inner()`). Do NOT reimplement it: the per-caller SIGNING FORMULAS (`memory_rpc::sign_body_bytes`, `integration_state_rpc::sign_body_bytes`) and the sign-time `validate_finite`/`validate_op` gates stay in their own crates; only the raw-text binding is shared
- NaN/Inf rejected in signed numeric fields (non-deterministic encoding otherwise)
- Depth is bounded by **serde_json's own 128-deep recursion limit** at `from_slice`/`from_str` (a deeper payload is a deserialize error, so it never reaches a signature check). There is no longer a Talos-side `MAX_CANONICAL_DEPTH` — it was deleted with `canonical_json_bytes` in #600, since nothing walks the tree to canonicalise it any more
- Per-subject concurrency semaphore + structured `target: "talos_rpc"` metric events with split `queue_ms` / `exec_ms`

**Verify-once rule for signed NATS messages** (`talos-workflow-engine/talos-workflow-job-protocol`, learned the hard way r300 / r301, 2026-05-05). Every signed message type (`JobResult`, `PipelineJobResult`, …) MUST have **exactly one primary `verify()` caller per controller process**. Passive observers (audit subscribers, metrics emitters, anything whose only side effect is an idempotent DB write) MUST use `verify_no_replay()` — HMAC + freshness without touching the process-local `JOB_NONCE_CACHE`. Two `verify()` calls against the same signed message will deterministically fail with `"result_nonce already seen"` because both insert into the same shared cache. The worker MUST single-publish each result to ONE NATS subject (reply inbox OR global audit topic, branched on `reply_topic` presence) — dual-publishing primes the cache race even when both consumers correctly use the split API. Background incident: see `memory/rpc_dual_verify_pattern.md`. Adding a new signed message type? Add both `verify()` and `verify_no_replay()` together up front; the prophylactic split is cheap, the regression is total (every job fails).

**Anything that needs to read or write `actor_memory` MUST go through `talos_memory::*` functions** — do not write inline `INSERT INTO actor_memory` SQL anywhere. The service is the only path that computes embeddings and runs graph-RAG entity extraction. Bulk clone is `talos_memory::clone_memories(pool, source_actor, target_actor)` — copies the live semantic+episodic memories (v0 rows pass ciphertext through; v1/v3/v4 rows are decrypt+re-encrypted to re-base their `actor_id`-bound AAD AND re-key onto the TARGET actor's org DEK), preserves `metadata`. Caller must verify both actors belong to the same user before invoking — this is a **tenancy/privacy** rule (don't copy one user's agent memory into another's), NOT a crypto one. (DEKs are per-ORGANIZATION, with a global DEK fallback for org-less data — there is no per-USER DEK; per-actor isolation comes from the per-`(actor_id,key)` HKDF-derived AEAD subkey under the actor's org DEK, so a cross-user copy would in fact decrypt fine. See the "Per-context AEAD subkeys + per-ORG root DEKs" section below.)

**This rule is now lint-enforced.** `make lint` runs `scripts/lint-structural.sh`, which fails on raw `INSERT/UPDATE/DELETE` against `actor_memory` outside `talos-memory/`, and on the legacy `value, value_enc` column projection (the pattern that broke 7 sites during Phase B's column drop). If you have a documented reason to write raw SQL, add `// allow-actor-memory-sql: <reason>` within 8 lines above the SQL — but the default path is `talos_memory::recall_*` / `persist_memory` / `clone_memories`.

**`metadata.kind` convention for synthetic outputs.** Any workflow that runs
`LLM-synthesize → persist → agent_memory::search` on the same actor MUST
stamp its writes with a stable `metadata.kind` label so future recalls can
exclude them. Without this, the LLM cites its own prior output as "source"
and hallucinations amplify on every run. Current labels in use:
- `meeting_prep` — pa-meeting-prep briefs
- `recall` — pa-recall Q+A pairs (convention: label matches workflow-name stem)
- `daily_brief` — pa-daily-brief summaries

**The `__memory_write__` protocol is OPT-IN per node.** A node persists to
actor_memory ONLY when its output JSON contains a `__memory_write__` key
with a non-empty `key` field — for example:
`{ "__memory_write__": { "key": "daily_brief/2026-04-21", "value": {...},
"metadata": {"kind": "daily_brief"}, "ttl_hours": 720 } }`. There is no
implicit "persist every node output" behavior. The hook fires at both
node-completion AND per-pipeline-step so chain-dispatched modules can
emit memory writes too.

Accepted `__memory_write__` fields:
* `key` (string, required) — the actor_memory key
* `value` (JSON, default null) — the stored payload
* `memory_type` (string, default `"episodic"`)
* `metadata` (JSON object, optional) — stored in the dedicated
  `actor_memory.metadata` JSONB column. Readers can filter via
  `agent_memory::search_filtered(exclude_kinds: [...])`. Use this to stamp
  synthetic LLM outputs with `metadata.kind` so they don't poison
  same-actor recalls. Non-object metadata is ignored. Available without
  the `agent-node` capability ceiling — the http-node ceiling is enough.
* `ttl_hours` (number, default 168) — TTL from now; semantic memories ignore TTL

**The envelope obeys the actor's WRITE CEILING (#750).** `actors.max_write_ceiling`
is ONE control with TWO enforcement surfaces, and until #750 only the worker's
existed. A module reaches `actor_memory` either by calling `agent_memory::set`
(refused in the worker by `TalosContext::write_ceiling_refuses`) or by RETURNING
this envelope, which the CONTROLLER persists on node completion — a route that
needs **no capability at all**: a `minimal-node` module — whose
`get_module_info.mutation_profile` is EMPTY, because `write_gated_ops` profiles
HOST OPS and the envelope is not one — wrote durable memory for a `readonly`
actor simply by returning a JSON object, and the execution reported success.
The profile was not wrong so much as SILENT about a real write route, which an
operator reading "this module mutates nothing" cannot tell apart; both
`write_gated_ops` and the tool's `note` now say so explicitly.
Now: the engine applies `talos_workflow_engine::write_ceiling_gate::apply_memory_write_ceiling`
at node completion AND per pipeline step, using the ENGINE's `max_write_ceiling`
(already narrowed for a sub-workflow by `bind_subengine_actor_and_ceilings`, so a
sub-workflow bound to a stricter actor is gated at the stricter ceiling). On
refusal the envelope is REMOVED (never merely flagged — a flagged envelope is one
`unwrap_or(false)` away from being honoured) and the engine-authored
`__memory_write_refused__` `{key, reason, ceiling}` is written in its place; the
node COMPLETES rather than fails (see the fn's docs for why — the worker path
returns an error to the GUEST and does not itself guarantee node failure either).
Like every engine-authored key it is **set-or-REMOVE, never set-or-inherit** — a
module cannot fabricate a refusal record. The DECISION is
`talos_workflow_engine_core::write_ceiling_denies(enforced, ceiling)`, shared with
the worker (whose copy is now a re-export) — do NOT hand-copy it; two paths
answering one question differently IS the bug. **`TALOS_WRITE_CEILING_ENFORCED`
must be set on BOTH processes** (the controller cannot read the worker's env);
`docker-compose.yml` and `values.yaml` now set both, and the chart's old
"controller side needs no change … Worker-only env" comment was false.
Defence in depth: `ControllerNodeHook::persist_memory_write_if_present` takes the
ceiling as a REQUIRED parameter, which is the only gate on `test_module` (that
tool now resolves the actor's real ceiling instead of hardcoding `Write`).
Audit parity is in the VOCABULARY (`op = "agent-memory-set"`,
`policy = "write-ceiling"` — the worker's exact tokens) but NOT the transport:
the worker's refusals also enter the hash-chained WORM ledger and the controller
has no `ExecutionLedger` producer, so its refusals reach the `talos_audit`
tracing target and `talos_memory_write_failures_total{reason="write_ceiling"}`
only. **Both instruments live on `ControllerNodeHook`; the ENGINE gate reaches
them by NOTIFYING it.** `NodeLifecycleHook::on_memory_write_refused` is called
from both engine gate sites and delegates to the single
`record_memory_write_refusal` that the hook's own in-method gate also calls —
one recording routine, two gates, no vocabulary drift. That notification is
load-bearing and was the one part of #750 nothing tested (even
`CaptureNodeLifecycleHook::MemoryWriteRefused`, added for it, had zero
consumers): delete it and the gate still gates perfectly while every instrument
goes permanently silent — a refusal indistinguishable from a write that never
happened, which is the exact reading the gate exists to remove.
`controller/tests/write_ceiling_memory_write_tests` now asserts the counter
moved EXACTLY once and the `talos_audit` event carried the right
`op`/`policy`/`ceiling`/`key`/`actor_id`/`node_id`, and that a PERMITTED write
moves neither. Both were verified firing on the live dev controller 2026-09-05
(`{reason="write_ceiling"} 1`; the WARN in the container log), so those
assertions are a REGRESSION GUARD proven by mutation, not a reproducer — saying
so matters more than implying they caught something.
**And "the `talos_audit` target" is exactly one thing: a target string on an
ordinary log line.** The controller installs
`registry().with(EnvFilter).with(fmt::layer()).with(otel_layer)` and no
per-target layer, so nothing subscribes to, routes, persists or alerts on
`talos_audit` — ~60 emitters share it as a grep convention that reaches stdout
and thence container logs. A reader who takes "audit target" to mean a durable
audit channel over-trusts it in exactly the sentence that contrasts it with a
WORM ledger. The METRIC is the only machine-readable half, and it is now
**pre-seeded at 0**: until 2026-09-05 the four `MemoryWriteError::metric_label`
reasons were seeded and this fifth, literal one was not, so on any controller
that had not yet refused anything (i.e. after every restart)
`{reason="write_ceiling"}` was ABSENT — "policy has never declined a write" and
"the gate is not wired" rendered identically. Deliberately NO alert on it: a
refusal is the policy working as designed, and the two live rules on this
counter select `reason="crypto"`/`"db"`, so a refusal cannot page anyone.
The pipeline-step gate site (`engine_dispatch_pipeline`) is dormant by CONFIG,
not by omission — every production entry point passes `ChainDispatch::Disabled`
(see `talos-workflow-engine/tests/chain_dispatch_gate.rs`), so that gate and its
notification fire only under `run_with_transport`, which no production caller in
this workspace uses. Routes deliberately NOT gated, for the record: the memory-RPC
`MemoryOp::Set` handler (`talos-rpc-subscribers`) still TRUSTS the worker's gate
— an asymmetry that only bites a mixed-config fleet; and operator-invoked writes
only. Routes deliberately NOT gated, for the record: operator-invoked writes
(`actor_remember`, `clone_memories`, `scaffold_actor` seeds, the GraphQL memory
mutations) plus platform-authored ones (`ml_digest`, consolidation/reflection,
the `upsert_scratchpad_trace` execution trace) are the OPERATOR's or the
PLATFORM's writes, not the actor's, and the ceiling does not speak to them.

**The signed-RPC routes are now gated too (#754).** #750 recorded that the
memory-RPC `MemoryOp::Set` handler "still TRUSTS the worker's gate". That trust
rests on an assumption the transport does not support: these requests are
HMAC-signed under `WORKER_SHARED_KEY`, which is FLEET-SHARED, so the signature
proves the sender holds a key — not that the sender ran a gate. Measured on
pristine main with enforcement ON at the controller: a signed `Set` naming a
`readonly` actor landed a row and the reply said `Ok`. The gate is
`talos_rpc_subscribers::write_ceiling::gate`, applied at every actor-attributed
mutation the CONTROLLER performs on a worker's behalf —
`MemoryOp::Set`/`Delete` (`talos.memory.op`), `IntegrationOp::Set`/`Delete`
(`talos.integration_state.op`) and a MUTATING `talos.database.query`. It uses
the SAME `write_ceiling_denies` predicate and the SAME `TALOS_WRITE_CEILING_ENFORCED`
reader (`write_ceiling_gate::controller_write_ceiling_enforced`) as the #750
envelope gate; the actor's ceiling comes from
`talos_actor_repository::read_actor_write_ceiling`, resolved by the SIGNED
`actor_id` only. **The read is three-valued and fails CLOSED**: `Ok(None)` (no
such actor) and `Err` (the rule could not be read) both REFUSE, with a
`write_ceiling_unreadable` reason distinct from the `write_ceiling` policy
reason — distinct for the OPERATOR (`talos_audit` field + `talos_rpc` outcome
tag), collapsed for the CALLER, because a reason-split reply would hand a
holder of the fleet key an actor-EXISTENCE oracle (the same argument
`caller_facing_unauthorized` makes). **Cost is zero when the flag is off**: the
`OnceLock` short-circuits before the query, so a default deployment is
byte-identical. With it on, one PK read of `actors` — measured 1.1 µs
server-side, 0.43 ms including the host round trip. A per-actor cache was
considered and REJECTED: a TTL on a security rule is a window in which a
revoked grant is still honoured, and the measured volume on this path is ~1
write/week. Enforcement is lint-enforced by **check 82** and pinned equal to
the worker's op list by
`write_ceiling::write_ceiling_tests::complement_is_worker_local` — every
ceiling-gated WORKER op must be classified as controller-served (and gated
here) or worker-local egress. `talos.state.write` is deliberately NOT gated:
the worker does not ceiling-gate execution `state` either (it is engine-internal
durability, not the actor's data), and a controller stricter than the worker is
the same defect in the other direction. **One finding worth carrying**: the
controller's `database.query` gate classifies read-vs-mutation from its OWN
AST, and the first version — `matches!(stmt, Insert|Update|Delete|Merge)` —
was WRONG. sqlparser 0.53 parses a data-modifying CTE
(`WITH ins AS (INSERT …) SELECT * FROM ins`) into `Statement::Query`, which
`controller_permits_data_statement` ADMITS, so a `readonly` actor could have
smuggled an INSERT past a gate that called it a read. The classifier now walks
the AST and breaks on any nested non-`Query` statement. The WORKER's twin
(`sql_stmt_type_is_read_only` over its validator's `stmt_type`) very likely has
the same hole and is NOT fixed here — the controller is currently the stricter
of the two for that shape.
**And the class is wider than this key.** The SAME hook, on the SAME
module-returned output and the SAME actor binding, also drives
`__ops_alert__` (→ `ops_alerts`) and `__ml_distill__` (→ ML dataset rows). Both
take the actor id, both refuse only when it is ABSENT, and neither consults the
ceiling — i.e. "a module bypasses the ceiling by returning a value" is true of
three output protocols and #750 gated one.

**DECIDED 2026-09-06: those two stay OUTSIDE the ceiling, and the reports
now say so.** #750 left it as "an operator policy call"; the call is that
`actors.max_write_ceiling` governs the ACTOR's own DATA PLANE — actor_memory,
integration state, sandbox SQL — and these two are PLATFORM ingestion that takes
the actor id for TENANCY, not because the rows are the actor's data: one is a
diagnostic, the other a training-example append. The live evidence is the
decisive part rather than the argument: of 5 `readonly` actors on this fleet
exactly ONE is `active`, it is bound to exactly ONE enabled workflow, and that
workflow's whole purpose is to emit `__ops_alert__` through this hook. Gating
the protocol would take the only live readonly actor's alert pipeline off the
air — the intended shape is `readonly` PLUS these protocols, not either-or. The
refusal that stays is the ABSENT-actor one: no actor is no tenancy principal.
What changed is the REPORTING, because "enforced" with no scope is read as
"nothing this actor emits reaches the database": `get_module_info`'s
`write_gated_ops` note, `set_actor_write_ceiling`'s description and
`security_audit.write_ceiling_enforcement` (detail + a
`parts.controller_gate.probe.ungated_output_protocols` array, from the single
`talos_security_audit::UNGATED_OUTPUT_PROTOCOLS`) all name both protocols.
`controller/tests/write_ceiling_hook_gate_tests` is a POSITIVE CONTROL: a real
`readonly` actor's `__ops_alert__` must still land a row, so a future "fix"
fails loudly (mutation-proved — early-returning from
`persist_ops_alert_if_present` gives `left: 0, right: 1`). `__ml_distill__` gets
NO equivalent test and the reason is measured, not asserted:
`spawn_distill_from_output` short-circuits on the process-global
`DISTILL_CONTEXT` `OnceLock` that sibling tests in one binary race (check 82's
own objection), and past it the flow needs an ML MAC key, an embedding provider,
a model and a dataset. Its half of the decision is pinned at the call site in
`talos-engine/src/node_hook.rs` and in the shared constant only.

**The control's own REPORTING was two defects behind the control (#760).**
Two, measured 2026-09-05, and they are the same shape one level up — a
misleading report about the thing being reported on.
**(a) `security_audit.write_ceiling_enforcement` described a controller that no
longer exists.** Its detail said, verbatim, "the enforcing gate lives in the
worker process, so the controller cannot exercise it from here", and graded
itself `config_presence`. True when #752 wrote it; false from #750 (the
`__memory_write__` envelope gate) and #757 (the signed-RPC mutation gate), both
of which run IN the controller and are PURE functions. So the audit's own
legend — `round_trip` = "a probe value was pushed through the real primitive and
the result inspected" — was reachable and unclaimed. `ControllerGateProbe::run()`
now drives both real chokepoints every run (`probe_envelope_gate` /
`probe_rpc_gate`, each owned by its gate's crate): a readonly probe must be
REFUSED and its envelope REMOVED, a write-capable one permitted, an unreadable
rule refused (fail closed), and an unenforcing deployment must permit
everything. A broken arm is `Status::Fail` + `RoundTrip` + `CRITICAL`, which
outranks every fleet finding. **The two halves are now rendered separately**
(`parts.controller_gate` at `round_trip`, `parts.worker_fleet` at
`config_presence`) because they are known to different standards and one word
must misstate one of them; the check's TOP-level `verification` stays **the
weakest of the facts its `status` rests on**, so `verification_counts` cannot
over-claim — promoting the whole check because half of it was exercised would be
the same overstatement in the other direction. Weight stays **0** (#752's three
reasons stand). New finding it can now make: fleet `all` + controller flag unset
is a **SPLIT CONTROL** `Warn`, not a `Pass` — the `some`-shaped state in the
OTHER direction from #757's, where every worker refuses a readonly actor's host
calls while the controller honours the same actor's returned envelope and its
signed-RPC mutations. `TALOS_WRITE_CEILING_ENFORCED` must be set on BOTH
processes and this is the check that can now say whether you did.
**(b) An RPC refusal was indistinguishable from a routine envelope refusal.**
#757 correctly said a refusal at the controller "means a worker sent a mutation
its own gate should have refused — a fleet-config signal worth alerting on,
unlike #750's envelope refusal", and routed it to `event_kind =
"rpc_write_ceiling_refused"` plus the per-subject `talos_rpc` outcome tag.
Measured live: **`talos_rpc` is a TRACING TARGET ONLY** — `curl
/metrics/prometheus | grep '^talos_rpc'` returns nothing and no RPC counter was
registered — and the three MEMORY routes folded into
`talos_memory_write_failures_total{reason="write_ceiling"}`, **the same counter
and label the routine envelope refusal uses, whose own HELP text says "do not
alert on it"**, while the integration-state and database routes incremented
NOTHING. So the fleet-config signal existed as prose and not as a series, and
the one counter carrying part of it actively instructed operators to ignore it —
check 58/65's class. Now: `talos_rpc_write_ceiling_refusals_total{subject,
reason}` (`subject` = the NATS subject, `reason` = `policy` | `unreadable`), all
six combinations PRE-SEEDED at 0 (absent ≠ zero: `increase(...) > 0` over an
absent series matches nothing), incremented at the ONE chokepoint
`write_ceiling::gate` so a new controller-served write op cannot forget it, and
alerted at `warning`/never-paging by `TalosRPCWriteCeilingRefusals`. The
`memory_write_failures` increment is KEPT — it answers a different question
("which actor-memory writes did not land") — and the double count is now stated
in its HELP text rather than silent. The log keeps the worker's tokens
(`RefusalReason::as_str`); the metric uses the short pair
(`RefusalReason::metric_label`), paired by an exhaustive match and pinned by
`refusal_reason_spellings_stay_paired`.
**No lint check was added, and that is a measurement, not an omission.** The
obvious guard — "a refusal chokepoint that logs an `event_kind` must also
increment a counter" — was measured before it was written: the workspace holds
**22** `event_kind = "…refus|denied|reject|blocked…"` emitters and **21** have no
counter within ±20 lines. A check cannot ship at 21, this repo does not re-add
baselines (check 52's own rule), and the adjacency proxy has known false
positives besides. So the count stays **84**.

Writes that omit `metadata` produce rows with `metadata IS NULL`, which
pass every filter — the right default for engine-trace style writes that
shouldn't be excluded from recall. Readers don't need an `"execution"`
entry in their exclude list.

Readers that want to skip synthetic entries call
`agent_memory::search_filtered(query, SearchOptions { limit, exclude_kinds })`
instead of the bare `search`. The filter is applied at the DB layer
(`talos_memory::recall_semantic_filtered`, parameterized `text[]` bind)
— not post-hoc in Rust, so it composes with limit + min_score cleanly.

## Two columns for one fact; a child that leaves no trace

Two operator-facing reports asserted a determinate negative for a state the
reader could not represent — the misleading-report class (checks 74, 76, 79/79b,
81) in two fresh shapes, both measured live 2026-09-05.

**"Unscored" over a score written an hour ago.** `workflows` carries TWO
readiness timestamps and TWO writers that each stamp only their own: the hourly
recompute in `controller/src/bootstrap/background.rs` writes
`readiness_computed_at`; the on-demand `get_readiness_breakdown` write-back
(`AnalyticsRepository::set_workflow_readiness_score`) writes
`readiness_scored_at`. Every reader anchored on the second, so with
`readiness_computed_at` set on 36 of 36 dev-fleet rows and `readiness_scored_at`
on **1**, `get_all_readiness_scores` answered `unscored_count: 27` of 28 and
per-row `score_state: "unscored"` **beside a `readiness_score` of 87**, telling
the operator to run a tool to compute a score that already existed; the flagship
reported `score_age_hours: 986` against a score recomputed that afternoon. The
previous fix here (MCP-1211) collapsed a two-STATEMENT write into one atomic
UPDATE — correct, and it left the predicate intact because it never saw the
**second writer**. The decision now has ONE home,
`talos_analytics_repository::readiness_state::classify_readiness_state`, which
reads BOTH columns, returns the EFFECTIVE (more recent) timestamp and NAMES the
scorer. **The columns are deliberately NOT collapsed**, and the reason is
measured rather than assumed: the two scorers are not the same function — the
arithmetic is shared (`compute_reliability_score` IS the background loop's
inline expression) but `get_readiness_exec_data` adds
`AND NOT (status = 'failed' AND acknowledged_at IS NOT NULL)`, so the background
number is the lower one on any workflow with an acknowledged failure in the
window. One timestamp cannot say which scorer produced the stored number, and a
`readiness_scored_at = COALESCE(...)` migration would relabel 35 background
scores as breakdown scores. So the READER was taught to read both, and
`readiness_population`'s `unscored` predicate now requires BOTH to be NULL.

**A daily sub-workflow "recommended for deletion".** `execute_subworkflow_graph`
runs a child IN-PROCESS and records no `workflow_executions` row — measured:
ZERO rows carrying `parent_execution_id` across the live table AND the archive,
platform-wide. `get_platform_hygiene_report`'s dormant query read that table
alone, so 3 of its 13 findings were children of ENABLED parents
(`cos-team-recall` — the flagship `pa-chief-of-staff`'s daily `team_gather`
sub-workflow — `pa-quality-judge`, and `pa-ask`), listed under *"Consider
disabling or deleting them with `batch_delete_workflows`"*. The row now carries
`runs_as_child_of: [parent names]` plus the note that `last_execution: null`
means NO EVIDENCE, and is EXCLUDED from the recommendation's count with the
exclusion disclosed (`excluded_child_workflows`, and the deletable names
enumerated) — it stays in the LIST, because an operator asking "what has no
executions?" should still see it. The exclusion is graph-derived and keyed on an
ENABLED parent; a self-reference does not protect a workflow, or every recursive
one would be permanently immune. The same query now reads
`workflow_executions_archive` too: the dormant window and `ARCHIVE_AFTER_DAYS`
are both 30 by default, so a live-only read is right by COINCIDENCE, and at
`ARCHIVE_AFTER_DAYS=7` every workflow that ran 8 days ago reads as never-run.

**The child-reference set has ONE implementation**, moved (not copied) into
`talos_workflow_engine_core::child_workflow_refs`, which
`talos_workflow_validation::collect_subworkflow_references` now re-exports. The
move closed the gap that function's own doc comment declared: the
`*_workflow_id` suffix convention covers seven of the engine's EIGHT
child-naming sites and structurally cannot see the eighth — `llm_dispatch`'s
`data.routes`, whose arbitrary class labels key the workflow ids — so
`get_workflow_risk_assessment` was blind to every route target too.
`child_workflow_ids_checked` is three-valued: `None` = the graph did not parse
(UNKNOWN), `Some(vec![])` = parsed and names nobody. A report that suppresses a
DELETE recommendation on the strength of "this is somebody's child" must not
read an unparseable parent as one that references nothing, so unreadable parents
are NAMED in `summary.child_workflow_exclusion.unreadable_parents` and in the
recommendation's own prose.

**What was measured and NOT changed** (stated so the population is visible
rather than rediscovered — the same discipline as the write-ceiling entry
above). A graph-blind execution read misleads **26** surfaces, not one. Two more
are DESTRUCTIVE and share the exact blindness: `stale_draft_workflows` (whose
`fix_all confirm=true` DELETES) and `session_start`'s `archive_stale_drafts`
(which ARCHIVES without confirmation), both keyed on
`status='draft' AND NOT EXISTS (SELECT 1 FROM workflow_executions …)`.

**That "latent today (no draft child on the fleet)" claim was refuted by this
report's own output, in the first run after it deployed** (2026-09-05 17:20Z).
`cos-team-recall` is `status = 'draft'`, and it appeared TWICE in one response:
in `dormant_workflows` annotated `runs_as_child_of: ["pa-chief-of-staff"]` and
excluded from the delete count, and two sections down in `stale_draft_workflows`
with no annotation, under *"1 draft workflow(s) have never been published or
executed in 7+ days — likely scaffolding leftovers … delete with
`batch_delete_workflows`"*. The graph scan that produced the first was scoped to
the DORMANT candidate list; nothing widened it. **A latency claim about a
population is only as good as the query that measured it, and the query used
was the one already fixed.**

Corrected severity, because "a `confirm=true` `fix_all` would have deleted the
flagship's child" is ALSO not what was measured. On the live fleet the preview
showed `stale_draft_workflows_to_delete: []` and
`substantive_drafts_skipped: [cos-team-recall]` — spared by
`is_substantive_workflow`, an authored-INTENT predicate that asks whether a
human shaped the draft and knows nothing about who runs it. So the delete was
blocked by COINCIDENCE, and a child with a bare graph was fully exposed:
verified against a pristine `origin/main` tree, where the same fixture with a
one-node empty-`data` graph puts the child in `draft_ids` with
`substantive_drafts_skipped` EMPTY. What WAS live and unconditional:
`session_start(auto_archive_stale_days: 7)` archived it, and
`batch_delete_workflows` removed it with no refusal of any kind.

Now: the same graph scan runs over dormant ∪ stale-draft candidates, the draft
row carries `runs_as_child_of` + `excluded_from_cleanup_reason`, the
recommendation's count excludes it with the exclusion disclosed
(`excluded_child_workflows`, `summary.child_workflow_exclusion
.excluded_stale_drafts_count`, and prose saying why count and list disagree),
`fix_all` gains a THIRD bucket `child_drafts_skipped` ahead of both existing
ones, and `archive_stale_drafts_excluding_children` SELECTs candidates → scans
→ UPDATEs **by id**, so the write is a subset of what was scanned by
construction. **The scan has ONE implementation** in the leaf crate
`talos-child-workflow-refs` (moved out of `talos-analytics-repository`, which
re-exports it): its three consumers — the hygiene report, the auto-archive, and
the delete-time guard — sit in three crates with no edge between them.

**REPORT and DECISION are different rules, and conflating them is how #758
stopped one section short.** A report row stays LISTED with its parents named;
a decision EXCLUDES it. They also disagree on the UNKNOWN case, deliberately:
`ChildReferenceScan::parents_of` (report) names only parents whose graph
PARSED, while `protection_for` (decision) additionally holds back a candidate
whose id merely appears in the text of a parent nobody could read — the scan is
scoped by a mention prefilter, so such a parent demonstrably mentions it, and
"I could not read the parent" is not "no parent dispatches into it". #758's
`octet_length(graph_json) <= $3` filter DROPPED an oversized parent from the
scan entirely, so its children read as unreferenced and it was not even named
under `unreadable_parents`; the row is now returned with a NULL body and
classified unreadable.

**Second finding, and it is the last line of defence: `delete_workflows` had no
reference guard at all.** It blocked only on running/queued executions — which
a sub-workflow never has — so every guard in this class lived in a report that
RECOMMENDS calling the tool, and the tool itself would remove a live child
without comment. The reference lives inside `workflows.graph_json` as TEXT, so
no foreign key can express it. `delete_workflows_checked` returns
`WorkflowDeleteOutcome { deleted, blocked_running, blocked_referenced }` — the
type change is the point, since it forces all three call sites to notice the
new refusal — and a parent that is ITSELF in the delete set does not block
(deleting a retired tree in one call must stay possible). `fix_all` consults it
even though its `draft_ids` were already filtered upstream: the preview an
operator confirmed may be minutes old, and a `sub_workflow` node added in
between is exactly what a graph-derived exclusion cannot see.

**Does a child's `draft` status mean anything at runtime? No, and this is worth
knowing before anyone "fixes" it by publishing.** `execute_subworkflow_graph` →
`WorkflowGraphStore::get_graph` reads the child's DRAFT `graph_json` column with
no version join, so `publish_version` changes nothing about how the parent runs
it and the "publish or delete" advice is half no-op and half destructive. That
half of the paragraph stands.

**Its other half was TRUE UNTIL 2026-09-07 and is now FALSE — it is rewritten
rather than left.** It read: *"ARCHIVING a child does not break dispatch either
(status is not read there), which is why the archive path is the least severe of
the three even though it is the only unattended one"*. The narrow dispatch gate
below closed exactly that: `get_graph` now returns `GraphLookup::Archived` and
the parent node FAILS naming the child and the word "archived". So **archiving a
child DOES stop it being dispatched**, and the auto-archive sweep is no longer
the least severe of the three destructive draft paths — it is now the one that
can take a live sub-workflow off the air unattended. The child-reference
exclusions #758/#760/#764 added to that sweep are what keep it from doing so,
and they are load-bearing in a way they were not when this paragraph was
written.

**What was measured and NOT changed here.** `AdvancedRepository::get_draft_workflows`
shares the same blind predicate and is left as-is: its only consumer is
`session_start`'s draft DISPLAY, which takes no destructive action (its
reasoning is in that method's doc comment, along with why it carries no lint
marker). And `__ops_alert__` / `__ml_distill__` remain ungated — no longer a
remainder but a DECISION, argued and reported above.

**The auto-archive remainder is now CLOSED (2026-09-05).** #758 recorded that
`session_start`'s auto-archive "still archives SUBSTANTIVE drafts — the exact
contradiction M-I fixed for `fix_all` in 2026-05" and left it, because it is a
behaviour change to an existing opt-in flag and archiving is reversible.
Measured on pristine `origin/main` before it was fixed, driving the REAL
`SessionBriefService`: the brief listed a shaped draft under
`unpublished_substantive_drafts` with `next_step: "publish_version with
workflow_id=…"` and reported `auto_archived_stale_drafts: 1` for that same row,
**in one response** — because `get_draft_workflows` was read BEFORE the sweep.
Both halves are fixed: the sweep now refuses a shaped draft, and the display
read moved BELOW the sweep, so neither list can name a row the same call
archived (that second half matters on its own — a STUB was listed with
`next_step: get_workflow_quickstart` moments after being archived, and no
substantive-ness rule would have closed that).

The predicate MOVED (not copied) to the leaf crate `talos-draft-heuristics`
(`serde_json` only), the reason `talos-child-workflow-refs` exists: the archive
sweep lives in `talos-advanced-repository`, which must not depend on a service
crate that pulls in four repositories. Three consumers, three crates, no edge
between them: `fix_all`'s auto-DELETE partition, the auto-ARCHIVE sweep, and
the draft DISPLAY. **The old home's doc comment claimed *"Both `session_start`
… AND `get_platform_hygiene_report fix_all` consult this helper so the two
surfaces never disagree"*, and it was FALSE — `session_start` carried an INLINE
COPY of the same 20-line walk.** Behaviourally identical, which is why nothing
caught it; an ALL-sites claim is worth only as much as the sites being unable
to drift.

`DraftIntent` is THREE-valued and `is_substantive_workflow` is a thin two-valued
view over it, byte-for-byte the old behaviour. The third value is for the paths
that WRITE: `is_substantive_workflow` answers `false` for "no markers" and for
"`graph_json` would not parse" alike, and on a sweep those are not the same
answer — `graph_json` is `text NOT NULL`, so an unparseable graph is storable,
and it is now held back under its own distinct reason. Same UNKNOWN-is-not-NO
rule the parent scan applies. Both exclusions run at the ONE chokepoint,
child-FIRST (matching `fix_all`'s partition — publishing a draft retires the
substantive reason and leaves the child reason standing), each skipped id
reported under its own reason (`auto_archive_skipped_children` /
`auto_archive_skipped_substantive`, with the `substantive_drafts_skipped`
wording `fix_all` already prints), and the UPDATE stays by-id over what was
classified.

**Deliberately NO force flag**, mirroring `fix_all`, which has had this
exclusion since 2026-05 with no override: the escape hatch is an EXPLICIT
operator action (`publish_version`, or `archive_workflow` /
`batch_delete_workflows` naming the workflow). An `include_substantive: true`
would re-enable an unattended destructive sweep over exactly the population the
rule exists to protect. The skip is disclosed in every response, so a draft
cannot quietly acquire permanent immunity, and the tool schema now says so
instead of promising to "archive draft workflows that have never been published
or executed".

**Blast radius, measured on the dev fleet 2026-09-05: ZERO additional skips
today.** 36 workflows, 11 drafts, 2 with no execution row; at any window ≥7 days
there is exactly ONE candidate, `cos-team-recall`, and #760's child rule already
spares it. So the substantive rule is LATENT on this fleet — stated plainly
rather than dressed up, since "latent is not live" cuts both ways and the
previous entry in this section was written the same way one day before the
condition it called latent went live.

**What was measured and NOT changed here.** The hygiene REPORT's stale-draft
recommendation counts a substantive draft as `deletable` and names
`batch_delete_workflows`, while `fix_all` — the DECISION built on the same rows
— excludes it. That is the report/decision split running the other way from the
child case (where the report lists and the decision excludes), it is advice a
human reads rather than an unattended write, and the sentence already offers
`publish_version` first; changing it would move a count an operator may have
wired up, so it is recorded. And a NON-substantive draft is still listed under
`in_progress_drafts` and swept in the same session — that is the flag doing
exactly what it was asked to do, and the ordering change means it is no longer
listed and archived in the same RESPONSE.

**No lint check was added, and the numbers are here so a future session need not
re-measure.** A "the substantive predicate has one home" detector — a file
naming both `retry_delay_expression` and `"SYSTEM_PROMPT"` outside the leaf
crate — reports exactly the duplicate on pristine `origin/main` and 0 on the
fixed tree: 1/1, trivially 100% precision, population ONE. That is a
single-instance historical class already answered structurally (one `pub` home,
`#[must_use]` on every entry point, and a DB test that drives both surfaces over
the same rows), so it is left unwritten rather than shipped as a check that has
never had anything to say. Note what that DB test does and does not cover,
because it was proven by mutation and not by reasoning: reducing the DISPLAY
half to branch 1 alone SURVIVED the first version of it, since every seeded row
agreed on both branches — the test now seeds a branch-1-only and a
branch-2-only shape, and the branch-2-only one (`data: {}` plus `retry_count`)
is the shape the live fleet's only stale-draft candidate actually has.

**#762 — the SCORING half: a child's reliability and freshness are UNMEASURABLE,
not zero.** #758/#760 fixed the DESTRUCTIVE readers; the same blindness also fed
three readiness scorers, the reuse report and a dead schedule-suggestion filter,
and those are fixed here. Reliability (50 pts) and freshness (20 pts) are read
from `workflow_executions` and from nothing else, so 70 of a child's 100 points
were scored from a table that is structurally silent about it. Measured on the
reference fleet 2026-09-05 — the WHOLE population of children, not a sample:
`cos-team-recall` 19 (the flagship's daily team gather), `pa-ask` 19 (runs per
inbound email), `pa-quality-judge` 19 (judge of three workflows),
`stress-05-child` 14, against a fleet otherwise at 40–87. The hourly loop
PERSISTS those numbers and `get_all_readiness_scores` sorts ascending, so the
flagship's own daily sub-workflow read as the least production-ready workflow on
the platform and `below_50_count` counted it.

**The DENOMINATOR shrinks; the score is not renormalised.** Two renderings were
rejected before this one and the rejection is the design: scoring the two
components 0 out of 100 is the determinate negative this whole class is about;
scoring the measurable 30 and SCALING IT UP to 100 fabricates — a documented,
low-risk child would report **100/100, fully production-ready** on zero execution
evidence, which is worse than the zero it replaces because it is confident in the
reassuring direction. So a child scores *N of `CHILD_MEASURABLE_MAX` (=30)*, its
unmeasurable components are NAMED, and `comparable_to_fleet` is false. The
shrunken denominator is what tells a reader the two numbers are not on one scale;
a number out of 100 does not, however it was derived. ONE home:
`talos_analytics_repository::readiness_basis::{ReadinessBasis, score_readiness}`,
called by all three scorers — what is unified is the BASIS, deliberately NOT the
reliability INPUT (the breakdown excludes acknowledged failures, the loop counts
them; #758 chose to disclose that and that decision stands). Child-ness comes
from `parents_of` (REPORT semantics), so an UNREADABLE parent leaves the workflow
on the full scale and the incompleteness travels by NAME
(`unreadable_parent_graphs` / `readiness_unreadable_parent_graphs`) rather than
silently. **Nothing to say ⇒ no key**: a full-scale workflow's response is
byte-identical to the pre-#762 one, except `get_all_readiness_scores`, which
emits `max_possible` on EVERY row — that list exists to rank rows against each
other, and a denominator present on some rows and absent on others is read as
"the others are out of 100" by exactly the caller who needs telling otherwise.
`below_50_count` EXCLUDES children with the exclusion disclosed
(`below_50_count_raw`, names, `measured`, `complete`), because a child is below
50 by construction; `avg_score` is deliberately NOT adjusted (it is a
population-wide SQL mean that the page cannot correct) and says so. The
page-scoped exclusion's COMPLETENESS is checked, not assumed: a child is ≤30, the
page is the ascending prefix, so a page reaching past 30 has already swallowed
every child — `child_exclusion_is_complete` computes that condition and the
summary says PARTIAL when it does not hold.

**Cost, measured rather than assumed.** The scan is one `LIKE`-prefiltered parent
read: **0.40 ms** at one candidate (the breakdown / `validate_workflow` path) and
**3.8–4.6 ms** with the whole 36-workflow fleet as candidates. The hourly loop
runs ONE scan per USER per tick — the 500-row batch is grouped by `user_id` and
each group's ids are the candidate list — against a loop that already issues
THREE queries per workflow; a per-workflow scan would have been 36 of these. A
failed scan falls back to full-scale (the pre-#762 answer) and is logged, never
aborts the tick.

**`get_workflow_reuse_stats` INNER-JOINs executions**, so `pa-ask` — dispatched
per inbound email, 0 rows live and archived — was ABSENT from the reuse tool, not
shown as zero. It now carries a SECOND list, `parent_dispatched`, with
`total_invocations: null` and `runs_as_child_of`: folding those rows into the
main list with a count of 0 was rejected because that list is RANKED by the count
they do not have. Bounded by `REUSE_ZERO_INVOCATION_SCAN_LIMIT` with truncation
disclosed.

**`get_frequently_executed_unscheduled`'s sub-workflow exclusion was DEAD for two
years and its own comment recorded the wrong lesson twice.** r242 wrote
`node.kind` / `data.sub_workflow_id`; r243 "corrected" it to
`module_id = 'system:sub_workflow'` / `config.sub_workflow_id` and wrote down
*"the lesson: verify the actual JSON shape via `get_workflow`"* — having done
exactly that and landed on a second shape the engine also does not write; r244
then fixed a real `::jsonb` cast on top, which made the query RUN, which is why
nothing looked broken. Measured live, both predicates as SQL against the real
column: r243's matched **0** nodes, the engine's `type` / `data.*_workflow_id`
shape matched **6** across 5 parents. The real lesson is that a hand-written
`graph_json` predicate is a SECOND IMPLEMENTATION of a question the engine
already answers — reading one workflow's JSON tells you one node kind's shape,
and the engine names a child through EIGHT keys, one of which
(`llm_dispatch`'s `routes`) is keyed by arbitrary class labels no key-name rule
can see at all. The exclusion now runs through the ONE scan, in Rust over a
widened page so removing a child does not under-fill the list of ten, and
`child_reference_shape_tests` pins it against the engine's parser rather than
against a string. Stated rather than sold: this exclusion is **vacuous on the
reference fleet today** — `HAVING COUNT(we.id) >= 3` already excludes every pure
child, so it bites only a HYBRID (dispatched AND directly triggered ≥3), of
which there are currently zero.

**`get_workflow_risk_assessment`'s cascading-failure check is DISCLOSED, not
fixed.** It `continue`s on a zero-row population, so on this fleet the
HIGH-severity check can never fire for any child. No risk entry is pushed (an
`info` row on every parent with a judge node would be noise on three of this
fleet's workflows); the population is emitted as
`cascading_failure_check.sub_workflows_unmeasurable` so "no cascading-failure
risk found" is legible as a statement about what was measurable. **The background
SLA-breach monitor is RECORDED and NOT changed**: it is an ALERTER with no
operator-facing field to disclose into, its `stats.total >= 3` gate can never
pass for a child, and the honest fix is a per-run record it does not have. So
`set_workflow_sla_threshold` on a child is silently inert. **BOTH sentences are
SUPERSEDED by the RFC 0012 P3 entry below (2026-09-07)**: the per-run record now
exists, the check reads it, and the alerter both reads it and has a channel to
say when it could not measure. Read them as the state before that entry, not as
current behaviour.

**What #762 could NOT guard, stated rather than implied.**
`controller/src/bootstrap/background.rs` is `mod bootstrap` inside `main.rs`,
i.e. bin-private, so no integration test can call its loop: deleting the loop's
`child_scans` lookup leaves every test green. What is covered by construction is
the shared decision — all three scorers call `score_readiness`, so removing the
classification from it turns three tests red (mutation-proved). The handler-level
wiring of the reuse list and the risk disclosure likewise has no test; the
repository methods and pure renderers behind them do.

**A lint for this class was BUILT, MEASURED and REJECTED — count stays 86.** The
candidate rule was *"a reader that scores or counts from `workflow_executions`
must consult the child scan"*. File-scoped, it reports **23 of 27** non-test
files on the FIXED tree and nearly all are legitimate (`checkpoint_store`,
`fence`, `stale_sweep`, `approval_gate`, the audit ledger, the secrets manager) —
those read execution rows for durability, authorization and crypto, not to make a
claim about use. Narrowed to an alternation of the five per-workflow reader
methods it reaches **7 call sites**, ~71% precision against pristine main, and
would ship at 2 with opt-out markers on the two surfaces deliberately left
disclosed — but its recall against the ~26 graph-blind surfaces is **27%**, the
alternation is the hand-maintained name list check 74 records as its own rot mode
(there is no derived method family here — the six readers have six unrelated
names in three crates), and, decisively, **it does not see the background loop at
all**: that scorer reads executions with raw `sqlx::query_as`, not a repository
method, so the lint would be green over the one writer whose number every other
reader reads back. A gate blind to the most consequential site in its own class
is the gate-that-doesn't-gate shape (#624, checks 64/65). The population is
recorded here instead. **The structural question these all share is
whether `execute_subworkflow_graph` should record a child `workflow_executions`
row** (`parent_execution_id` / `root_execution_id` exist and are written only by
replay today). Measured before deciding: ~225 estimated child runs/day, 98.6% of
them one workflow; **163** `FROM workflow_executions` occurrences across 28
non-test files, of which exactly **2** carry a `parent_execution_id IS [NOT]
NULL` filter — so recording children would silently double-count in 161 places,
including every fleet total, error rate and cost aggregate. That is a
platform-wide change, not a report fix, and it is recorded here rather than
attempted.

**2026-09-07 — a third pair, and the report read one half of it: `workflows.status`
vs `workflows.is_enabled`.** `get_platform_hygiene_report` recommended *"10 enabled
workflow(s) have had no executions in 30+ days. Consider disabling or deleting them
with `batch_delete_workflows`"* and listed them under `deletable`. **EIGHT of the ten
were `status = 'archived'`** — the operator it was advising had already retired them.

**The mechanism is the readiness-timestamp one exactly.** `is_enabled`
(`20260314001600`) is the OPERATOR's pause toggle; `status` (`20260318000000`) is
the LIFECYCLE. Two writers, and neither touches the other's column: the six
`UPDATE workflows SET status = 'archived'` sites
(`talos-workflow-repository/src/workflows.rs:963,1346,1357`,
`talos-advanced-repository/src/lib.rs:1880,2362`,
`talos-actor-repository/src/lib.rs:1071`) never clear `is_enabled`, and
`set_workflow_enabled` never moves `status`. Measured on the reference fleet
2026-09-07: `active/t 17, archived/t 8, draft/t 11` — **every archived row still
reads `is_enabled = true`**. The dormant query predicated `w.is_enabled = true`
with NO status clause; reproduced verbatim against the live database it returns 13
rows, 8 of them archived, and minus #760's three child exclusions that is the 10
the recommendation named.

**The columns are deliberately NOT collapsed and there is NO migration flipping
`is_enabled` on archived rows** — the readiness-timestamp argument applies
unchanged: the two writers record two different operator acts, one column cannot
say which happened, and a backfill would relabel eight archives as pauses that
never occurred. The READER changed.

**The predicate has ONE home**, the leaf crate `talos-workflow-liveness`
(no dependencies), and it is TWO predicates rather than one, because the second is
not a weaker version of the first:
* `is_live` = `status = 'active' AND is_enabled` — published and not paused.
* `is_dispatchable` = `status <> 'archived' AND is_enabled` — what the PLATFORM can
  still run. A DRAFT counts: a parent dispatches a child's `graph_json` column with
  no version join and no status predicate (the "does a child's `draft` status mean
  anything at runtime?" entry above), and **4 draft workflows on this fleet carry
  enabled schedules and fire today**, so folding draft into "not live" for an
  operational population would be wrong in the loud direction.

The Rust predicates are EXACT twins of `live_sql` / `dispatchable_sql` /
`retired_sql`, including on an unrecognised `status` — the column has **no CHECK
constraint**, so `WorkflowLifecycle::Unknown` is a real state (one live query still
filters `status = 'published'`, a value nothing writes, and the pre-existing
`dormant_child_workflow_tests` seeds exactly that). An unknown status is NOT live
and IS dispatchable on both sides; `rust_and_sql_agree_on_every_status` EVALUATES
the rendered fragment rather than comparing strings, so the asymmetry is pinned as
the SQL's rather than quietly fixed on one side.

**Five sites now read it**, and the count is the point: the analytics file already
spelled the same predicate correctly FOUR times
(`is_enabled = true AND (status IS NULL OR status != 'archived')` — the `status IS
NULL` arm dead, since the column is `NOT NULL`, verified against the live catalog)
while the fifth, the dormant query, forgot. `scan_child_parents` and
`list_enabled_graph_json_for_boot_warmup` were right too and spelled it a fifth and
sixth way (`!=` and `<>`, in two crates). Six correct sites, three spellings, one
defect between them.

**EXCLUDED is not DROPPED.** `summary.archived_excluded` carries the count, up to 25
names, `names_truncated` and a note; the cleanup recommendation's sentence names
them and says why its list is shorter; `affected_count` now equals what `deletable`
contains. The read is a SEPARATE statement over the SAME window and the SAME
dormancy test with `status = 'archived'` instead — a subset of what the list
scanned, by construction — and `count(*) OVER ()` carries the true total past the
name cap. A FAILED read renders **null, never 0**: `archived_excluded: 0` claims the
operator has retired nothing, which is one word away from the sentence this
exclusion exists to stop the report making. That arm is unreachable from a DB test,
so `an_unreadable_archived_exclusion_is_null_not_zero` drives the pure renderer with
a ledger that marks the field unmeasured — it was a **measured SURVIVOR** of the DB
suite before that test existed.

**What was measured and NOT changed, and it is the severity of the whole class.**
No execution path in this workspace filters on `workflows.status` at all. Proved
with a scratch row — an archived workflow with `is_enabled = true`, an enabled
schedule due one minute ago and an enabled webhook — driven through the VERBATIM
production SQL: the scheduler due query (`talos-scheduler/src/lib.rs:1104`), the
post-due workflow load (`:1584`), the webhook dispatch read
(`talos-webhooks/src/router.rs:1763`), `resolve_by_capabilities` and
`WorkflowGraphStore::get_graph` **ALL returned it**. So archiving does not stop a
workflow being scheduled, webhook-triggered, capability-dispatched,
chain-dispatched, sub-workflow-dispatched, called, triggered or enqueued;
`is_enabled` is the only execution-path gate and it is enforced in RUST, never in
SQL, at four places (`trigger.rs:203`, `call_workflow`, `trigger_workflow_as_actors`,
`is_workflow_enabled` for retry/replay), while `bulk_trigger_workflow` and
`enqueue_workflow` have none. The SCHEDULER reads neither `workflows` column, so
`disable_workflow` does not stop a scheduled run either — the schedule's own
`is_enabled` is the pause control there. **LATENT on this fleet**, stated plainly:
the 8 archived rows have 0 enabled schedules and 0 enabled webhooks. Closing it is a
fleet-wide behaviour change with its own blast radius (those 4 draft schedules among
them), not a report fix, and it is recorded rather than attempted. `fix_all` and
`session_start`'s draft sweep were checked and are unaffected: both key on
`status = 'draft'`, a lifecycle filter that excludes archived rows by construction.

**Check 87 was BUILT, MEASURED and SHIPPED, and the numbers say why it is
window-scoped.** *"A `workflows` liveness predicate must name the shared home."*
FILE-scoped it reports **6** on pristine main of which **3** are the
`workflow_schedules.is_enabled` false positive (50% precision, shipping at 3 markers
on correct code) — and worse, it would have been GREEN over the defect once any one
of the four correct siblings in the same file named the home, which is check 86(a)'s
stated limit becoming fatal. WINDOW-scoped (1400 chars back, 400 forward, whole-line
comments stripped, `workflow_schedules` windows excluded) it reports **SEVEN on
pristine main, every one a real `workflows` liveness predicate, 0 false positives,
and 0 on the fixed tree**. Stated honestly: **7-of-7 against the RULE, 1-of-7 as a
BUG detector** — the other six were correct and merely unrouted (check 85(b)'s
framing). `--count` moves to **87**.

Three mutations, all red: reinstating the dormant defect reports it at that exact
line; a COMMENTED-OUT gate does not vouch (whole-line comments are stripped first —
check 73's trap, which cost this check one false finding on its own doc block before
the strip went in); and a tree where the shape has vanished FAILS LOUDLY rather than
passing. That third one needed a two-part tripwire and the first version got it
wrong in the reassuring direction: once a site is ROUTED the literal
`is_enabled = true` disappears from it, so a raw-literal-only tripwire reported
"found nothing" on the fully-fixed tree — measured, not imagined. It now counts raw
windows PLUS rendered `*_sql(` call sites.

### "Archived" must mean "will not run" — the NARROW dispatch gate (2026-09-07)

**The entry above closed the REPORT half and recorded the other half without
fixing it**: *"No execution path in this workspace filters on `workflows.status`
at all"*, proved with a scratch row that an archived workflow with an enabled
schedule and an enabled webhook was returned by all five verbatim production
reads. This closes it. The operator's decision is the NARROW gate and nothing
wider: **every dispatch path refuses `status = 'archived'`, and nothing else
changes.** A DRAFT still dispatches — 4 drafts on the reference fleet carry
enabled schedules and fire today — and `is_enabled` keeps exactly the meaning
each path already gave it, including the paths that have never consulted it.
`dispatchable_sql` is deliberately NOT the predicate used here: it also requires
`is_enabled`, which would have been a second, unauthorised behaviour change
wearing a one-word diff. The gate is `talos_workflow_liveness::not_retired_sql`
/ `is_not_retired`, and `not_retired_is_weaker_than_dispatchable` pins the two
apart so a future edit cannot quietly promote one to the other.

**The five paths that entry named were not the population; there are 35, and
two of its five descriptions were wrong.** The due query
(`talos-scheduler:1103`) reads `workflow_schedules` ALONE and never joins
`workflows`, so there was no predicate to add there and the gate had to sit at
the post-due load; and the named `talos-schedule-repo` join is a LISTING, not
the due query. More importantly, **"no execution path filters on `status`" was
itself false by one site**: `ActorRepository::get_workflow_graph_for_user`
(`talos-actor-repository/src/lib.rs:2050`) has carried
`AND (status IS NULL OR status != 'archived')` in SQL all along, and its only
caller is `handoff_to_actor`. So handoff was the one dispatch surface that
refused — while REPORTING the refusal as *"Workflow not found or access denied"*,
false on both clauses, because the filtered read returned `None` and the caller
had nothing else to say. That claim is corrected in the crate's own module doc,
in check 87's entry, and the read now returns the status so the caller can
classify it (`HandoffError::WorkflowArchived`).

**One gate covers seven surfaces because the enum forces it to.** The scheduler,
the webhook router, `trigger_workflow`, `call_workflow`, `bulk_trigger_workflow`,
`trigger_workflow_as_actors` and `enqueue_workflow` all mint their execution row
through `create_execution_under_concurrency_limit` (or its batch twin), whose
`SELECT … FOR UPDATE` on `workflows` was already there — so `status` rides along
on that read, the gate costs **no extra query**, and it is atomic with the INSERT
it guards. `ConcurrencyAdmission::WorkflowArchived` is a NEW VARIANT rather than
a boolean, and that is the point: the enum is matched exhaustively at all seven
sites, so the compiler asked each of them how it renders the refusal. Same move
`WorkflowDeleteOutcome` made in #758. The batch twin gets a `archived: bool`
FIELD instead, and the asymmetry is argued rather than sloppy: there
`inserted == 0` already refuses whether or not the caller reads the flag, so the
flag buys the caller the ability to say WHY — "throttled" invites a wait for
capacity that will never arrive.

**The paths that mint no row, or mint it elsewhere, carry their own gate.**
`retry` and `replay` reuse an existing row; the continuation trigger (approval
resumes, suspension resumes, and the Gmail push-notification WORKFLOW branch)
writes elsewhere; the sub-workflow child dispatch mints none by design. Those
read `WorkflowRepository::dispatch_lifecycle` — one PK read of `workflows`, the
same shape and cost as #754's `read_actor_write_ceiling` — returning
`WorkflowDispatchLookup::{Dispatchable, Retired, Absent}`, `#[must_use]`, with no
`Into<bool>`: a boolean gate is one `unwrap_or(true)` from fail-open, and its
caller could not tell a retired workflow from a deleted one when it renders the
refusal. Note `replay` already read `is_workflow_enabled` — the OTHER column —
directly above, and would have passed a retired workflow on the strength of it.

**CLASSIFY where there is one named workflow; FILTER IN SQL where there are
candidates.** `get_graph` is classified (`GraphLookup::{Found, Archived, Absent}`,
the `ExecutionLookup` shape from #748) so a parent node fails with a message
naming the child and the word "archived" instead of "not found", which would send
its author hunting a deletion that never happened. The chain fan-out,
`resolve_by_capabilities`, `resolve_by_name` and the `get_graphs` cache prefill
filter in SQL, and each has a reason: the fan-out's `LIMIT` must be applied over
real candidates or retired rows displace live ones from the chain set; the two
resolvers are `ORDER BY … LIMIT 1`, so a read-then-refuse would let a retired
candidate SHADOW a live one; and the cache prefill is only a warm-up, so an
archived child misses it and falls through to `get_graph`, which reports the
refusal once, with one wording.

**`resolve_by_capabilities` is the one site here that is NOT latent, and it is
the reason this shipped as more than tidying.** Measured on the reference fleet
2026-09-07: all 8 archived rows carry non-empty `capabilities`
(`email-delivery`, `sub-workflow`, `world-http`, `actor-memory-read`, …), and
that resolver is `WHERE capabilities @> $2 ORDER BY updated_at DESC, id DESC
LIMIT 1` with no lifecycle predicate — so a retired workflow was not merely a
candidate for capability dispatch and A2A, it could be the WINNING one. The DB
test seeds the retired row with the NEWER `updated_at` for exactly that reason,
and the main-vocabulary twin fails on pristine main by returning it.

**Everything else is latent, and saying so plainly is the point.** The 8 archived
rows have **zero schedule rows** (not merely zero enabled ones) and **zero
webhook triggers**. And the child question the brief asked to measure: **ZERO
archived children under enabled parents** — in fact zero archived workflows are
mentioned in ANY workflow's `graph_json`, whatever the parent's status. That was
measured WITH A CONTROL, because a query that finds nothing proves nothing until
it is shown able to find something: dropping the archived filter returns 6 real
parent→child mentions (`cos-team-recall`, `pa-ask`, `pa-quality-judge` ×3,
`stress-05-child`). So the sub-workflow half of this change can alter no live
behaviour today.

**Refusals are VISIBLE to the OPERATOR and OPAQUE to an unauthenticated caller.**
`talos_dispatch_refused_total{path, reason="archived"}` is pre-seeded at 0 for
all 12 paths that classify in Rust, incremented at one helper
(`talos_metrics::record_dispatch_refusal`) taking a TYPED
`DispatchPath` so a new surface cannot spell a label the constructor never
seeded. **Nothing alerts on it**: a refusal is the policy working, and an alert
here would train operators to ignore the one series that answers *a schedule
stopped firing — is the platform refusing it, or is the scheduler broken?* The
scheduler's per-tick line is **DEBUG**, not WARN, for check 69's reason (an ERROR
that fires forever on a healthy fleet trains operators to ignore ERROR); its
durable signal is the counter plus `scheduler_dispatches_total{outcome="denied"}`
— **`DENIED`, not `SKIPPED`, and the existing partition already made that call**:
that label's own doc says it is for a fire "refused by POLICY … chronic
configuration states that are unchanged by how many schedules came due at once",
which is this exactly, and folding it into `SKIPPED` would put a permanent
configuration state inside the startup-herd alert.

**The scheduler DOES NOT disable the schedule row, and that was a decision.**
Option (b) in the brief was to disable it on first refusal with a WARN. Rejected:
archiving is REVERSIBLE, so a self-disabling schedule would make un-archiving
silently not resume — a second, invisible operator act the platform performs on
the operator's behalf, which is the same two-columns-disagreeing asymmetry this
whole class is about. A permanently-firing WARN is check 69's shape. So option
(a), with the per-tick line at DEBUG.

**The webhook tells the caller nothing.** It answers exactly what it answers for
a workflow that is not there — `404 "Workflow not found"`, byte-identical — and
that is the one place in this change where a refusal is deliberately rendered as
an absence: an inbound webhook caller is unauthenticated with respect to the
workflow, and a reply that distinguishes "archived" from "no such workflow" is an
existence oracle for anyone who can guess a trigger id (the
`caller_facing_unauthorized` argument, and #754's collapsed
`write_ceiling_unreadable` reply). The operator keeps the distinction in the
counter and a WARN — WARN rather than the scheduler's DEBUG because a webhook
refusal is one inbound request rather than a recurring tick, so it cannot become
permanent noise. **There was no paused-workflow response to mirror, and that was
MEASURED rather than assumed**: the webhook path consults `workflows.is_enabled`
NOWHERE, in SQL or in Rust, so a disabled workflow still fires by webhook today.
The narrow gate does not change that — it is the other column.

**Sites deliberately NOT gated, argued rather than omitted.** (1) **Resume and
crash recovery** (`claim_stuck_execution_for_resume`,
`claim_waiting_execution_for_resume`, the resume auth gate): these FINISH a run
that was already admitted, and refusing would strand a waiting approval gate the
moment an operator archived the workflow — turning a reversible lifecycle change
into permanent loss for an in-flight run. The gate is about what the platform
will START. (2) **`test_workflow`, `test_workflow_draft`, GraphQL
`testWorkflow`**: an operator explicitly asking to test ONE named workflow is not
the platform deciding to run it, and refusing would remove the only way to check
a workflow before un-archiving it. This is the place a reader might reasonably
expect a refusal and not find one, so it is stated rather than left to be
discovered. (3) **Module replay**: replays a MODULE against recorded inputs; the
graph is read to rebuild a node's config, not to run the workflow.

**The chain fan-out's refusal is SILENT, and that is a stated limit rather than
an oversight.** `talos_dispatch_refused_total` has no `chain` label because that
site is a capped SET read, not a per-request refusal — there is no one workflow
being refused to count, and seeding a label nothing increments is the defect
check 58 exists for. The same applies to the two resolvers and the cache
prefill. Four of the sixteen gate sites are therefore uncounted, by construction.

**Guard, and what it does and does not cover.**
`controller/tests/archived_dispatch_gate_tests` (8 tests, CTRL_TESTS) drives the
REAL admission chokepoint, the REAL `WorkflowGraphStore` reads, the REAL
`dispatch_lifecycle` and the REAL handoff read. Two properties are deliberate:
it asserts on **ROWS**, not just on the returned variant — an earlier version of
#754's write-ceiling test passed because the INSERT would have failed anyway and
survived the gate being deleted, and the first draft of THIS file reproduced that
exactly (passing `actor_id: None` made both CONTROLS die on a NOT NULL constraint
while the archived case "passed") — and every test carries an **ACTIVE and a
DRAFT control**, so a gate widened to `status = 'active'` fails here rather than
looking like a stricter version of the same thing.

**Measured RED on pristine `origin/main`, by assertion and not by compile
error**: six main-vocabulary twins were run in a real `git worktree` of `1a13ad6b`
against its own migrated database, and **6 of 6 FAILED BY ASSERTION** — the
admission gate admitted an archived workflow and wrote the row, the batch twin
queued 3, `get_graph` handed back the archived child's graph, the capability
resolver returned the RETIRED workflow as the winner, name resolution resolved
it, and the handoff read hid the row. Zero failed by compile error. The twins are
a scratch artefact and are not committed.

**No lint check was added and `--count` stays 87.** The candidate — *"a
`workflows` read that feeds dispatch must name the liveness home"* — was measured
before it was written and REJECTED twice over. It cannot be scoped by SQL shape:
the 35 dispatch reads share no predicate (`WHERE id = $1 AND user_id = $2` is
also how ~40 report and authoring reads spell themselves), so a shape-scoped rule
is ~50% precision at best. Scoped instead to the FILES that dispatch, it reports
the 33 files carrying any `FROM workflows` and would ship at ~25 markers on
correct code. And decisively, it would be **green over the very defect it is for**:
every gate site in this change now names `talos_workflow_liveness`, so a
file-scoped rule is satisfied by ONE gated read vouching for every other read in
the same file — check 86(a)'s stated limit, which check 87 already had to
window-scope around. Check 87 does not cover this either: its window looks for a
LIVENESS predicate over both columns, and the dispatch gate is one column. The
structural answers that ARE stronger than a grep: `ConcurrencyAdmission` and
`GraphLookup` and `WorkflowDispatchLookup` are exhaustively-matched enums, so a
new dispatch surface cannot be added without the compiler asking what it does
with a retired workflow; `record_dispatch_refusal` takes a typed `DispatchPath`;
and the DB tests carry a DRAFT control at every site.

**2026-09-06 — the ANSWER: `sub_workflow_runs`, the child-run ledger (RFC 0012 P1).**
Everything above this line teaches a reader to say *"no evidence"* instead of
*"never ran"*. None of it can ANSWER the question, and the structural question
#762 recorded — *should `execute_subworkflow_graph` write a `workflow_executions`
row?* — is answered NO for the reasons measured there (161 of 163 reads carry no
`parent_execution_id` filter; `budget_precheck` counts execution rows, so a
parent with a child would be billed twice; the retention sweep would split one
tree across two tiers). RFC 0012 takes shape B: a separate, narrow table written
at the dispatcher chokepoint, with no payload columns, RLS from its first
migration, and its own retention tier in the existing pass at
`archive_after_days + purge_after_days` (no FK, because archival is a DELETE plus
an INSERT and a CASCADE would erase the ledger at day 30 while the parent lives
to day 60).

**P1 covers**: the migration + RLS, `ChildRunRecorder` in
`talos-workflow-engine-core`, the leaf repo `talos-child-run-ledger`, the ONE
chokepoint write, retention, `since()`, and the two smallest honest consumers —
`get_execution_lineage` gains `child_runs` under the anchor, and
`get_workflow_reuse_stats.parent_dispatched` gains `child_runs_since_ledger`
beside `ledger_since`. **P2** is the four uncovered dispatch kinds plus
readiness / hygiene / the dormant lists; **P3** the SLA monitor and the
cascading-failure check.

**The RFC's own premise was REFUTED before anything was written, and the
correction is the part to remember.** `execute_subworkflow_graph` is NOT the one
path every child takes. Enumerating every `AdapterSet::into_engine_with_graph`
site — the only way a child graph becomes a running engine — finds THREE: the
chokepoint, `run_dispatched_subworkflow` (`dispatch`, `capability_dispatch`) and
the agent-loop body's per-iteration hydration. So P1 records five node kinds
(`sub_workflow`, `judge`, `ensemble`, `reflective_retry`, `llm_dispatch`) and is
structurally blind to four. On the reference fleet those four are LATENT — of 36
workflows the only child-dispatching node kinds present are `sub_workflow` (3)
and `judge` (3) — and *"latent is not live"* cuts both ways, so the gap is NAMED
in `talos_child_run_ledger::UNRECORDED_DISPATCH_KINDS` and DISCLOSED by both
consumers rather than left to read as "this child never ran". The table's CHECK
admits exactly the five kinds that have a writer: `agent_loop` was in the RFC's
draft list and is deliberately absent, because a value nothing writes is the same
defect as a seeded metric label nothing increments.

**2026-09-07 — P2: the readers learn to read the ledger, and the four blind
dispatch kinds are closed.** P1 could ANSWER "did this child run"; nothing
asked it. Four readiness surfaces and two hygiene lists now do.

**Readiness.** `ReadinessBasis` gains `LedgerMeasured`. A child with ≥
`LEDGER_MIN_RUNS` (**3**) recorded runs in the 30-day window is scored on the
FULL 100 with reliability = the ledger's success rate and freshness = the age
of its newest recorded run, both through the SAME `compute_reliability_score` /
`compute_freshness_score` the fleet uses — the INPUT moves, the arithmetic does
not. Below the floor the child KEEPS the 30-point denominator and the shortfall
is disclosed with the count and `ledger_since`; it is NEVER scaled up, which is
#762's second rejected rendering and stays rejected. **Why 3, argued from
#762's own reasoning**: 1 promotes on one observation, so a single failure
reports reliability `0/50` as a fleet-comparable fact — the determinate
negative in a new shape; 10 (the ramp's saturation point) keeps a child that has
demonstrably run nine times on a denominator whose stated reason is "nothing can
measure this"; 3 is the smallest number from which a success RATE is a rate, and
the ramp already discounts it (a perfect child at n=3 earns 15 of 50). The floor
protects the DENOMINATOR claim, not the arithmetic. **`ReadinessBasis::from_scan`
was DELETED**: it had zero production callers by the end of P2 and exactly one
behaviour — silently scoring every child on 30 — so a scorer that FORGOT the
ledger would have been indistinguishable from one that could not READ it.
Callers pass an explicit `Option<ChildLedgerEvidence>`; `None` STATES "not
consulted", the same reason P1 made `ChildRunSite` an enum and not an `Option`.
All FOUR surfaces read it — the three `score_readiness` callers plus
`get_all_readiness_scores`, which derives `max_possible` from the basis instead
— and the `below_50` exclusion follows the BASIS
(`ReadinessBasis::is_unmeasurable_child`), not child-ness: a ledger-measured
child scoring 47 is a REAL below-50 finding, and excluding it would hide the
platform's most-used sub-workflows from the one count that would notice them
degrading.

**Hygiene.** The dormant and stale-draft child rows gain `last_child_run_at`,
`child_runs_since_ledger` (null, never 0, before `ledger_since`) and the
`ChildRunEvidence::note` that refutes the stale-draft list's own "never
executed" premise. The `execution_cost_rollup` proxy is **KEPT and DEMOTED, not
deleted**, and the reason is a measurement: it is the only thing that can speak
for the period BEFORE the ledger's first row, which was **~11 h old against a
30-day window** the day this shipped. Its caveat now records the number that
supersedes it — measured 2026-09-07, the worst case is **0%** recall and not the
~5% P1 recorded: one child whose parent ran **5085** times in 30 days (461 of
them in 48 h) has ZERO rollup rows in the whole window and a proxy timestamp 45
days old. Once `ledger_since` is older than the 30-day window the proxy adds
nothing and can be removed — an operator loses nothing then, and everything
before the floor now.

**The four uncovered dispatch kinds are RECORDED, and the "different shape" the
RFC predicted was the shape the file already used.** `dispatch` /
`capability_dispatch` (`run_dispatched_subworkflow`) and the per-iteration
`agent_loop` / `react_loop` body now write. `execution_id` was already in scope
at all three reactor call sites, so threading was never the obstacle; the
obstacle was that the loop body's `async move` captures the adapter set and NOT
`self`. `ChildRunReporter` — a small `Clone` value carrying the recorder, the
sanitizer, the parent workflow id, the RESOLVED node label and the depth — is
built from `&self` and captured beside `sub_binding`, which the same function
had been doing for the same reason since #504. **The INSERT is still in exactly
one function**; what moved is where its inputs come from. The loop records ONE
ROW PER ITERATION (five iterations are five child runs; folding them would make
the ledger disagree with `iterations_run` and with the fuel those iterations
burned), and `ReActLoop` records `react_loop` even though it shares
`try_dispatch_agent_loop` — the ledger records what the AUTHOR wrote.
`UNRECORDED_DISPATCH_KINDS` is now EMPTY and is **kept rather than deleted**: an
empty list is a CLAIM, and deleting the constant removes the only place that
claim can be contradicted when a tenth kind arrives without a writer. Migration
`20260907020000` widens the CHECK to nine values (a NEW migration, never an edit
of the applied one).

**Cost, measured rather than assumed.** The hourly loop adds **two queries per
USER per tick** — a cached floor read and one grouped `= ANY($1)` count over
that user's child ids, narrowed to rows the child scan already calls somebody's
child, so a batch with no children costs no query at all. Against a loop already
issuing THREE queries per workflow (108 for the 36-workflow fleet) that is ~2%
more statements. On a standalone replica carrying P1's three indexes: at 13 500
rows (60 days at ~225 runs/day) the batched count is 0.96–1.17 ms and
`since()` is **1.7–1.9 ms as a SEQ SCAN**; at 135 000 rows they are 9.0 ms and
**14.4–15.5 ms**. None of the three P1 indexes leads with `started_at`, so
`MIN(started_at)` is linear in the table — and P2 takes that read's callers from
two to five. The migration therefore adds `(started_at)`, measured at
**0.036–0.045 ms** (Index Only Scan) on the same 135 000 rows, i.e. ~400x, for
one more b-tree on an append-only table.

**What is NOT covered, measured rather than implied.** (SUPERSEDED for the two
write sites by the P3 entry below — the mutation named here is now CAUGHT by
`talos-workflow-engine/tests/child_run_dispatch_recording.rs`, and it was
re-run against the pre-existing suite to confirm this paragraph was true when
written.) Deleting the `record`
call at the tail of `run_dispatched_subworkflow` leaves every
`talos-workflow-engine` unit test AND both ledger DB binaries GREEN — a measured
SURVIVOR, not a hypothetical. That function is private and the loop body sits
inside a `tokio::time::timeout`'d `async move`, so driving either needs a full
reactor run over a graph with a `dispatch` or `agent_loop` node, which the P1
harness does not build. What IS covered by construction is the SHARED write site
every path now routes through: gutting `ChildRunReporter::record` turns four
`child_run_ledger_tests` red. The reference fleet has **zero** nodes of those
four kinds, so there is nothing to read live yet either — both halves stated
rather than left to look like coverage. **No lint was added and `--count` stays
86**: the candidate ("a readiness scorer must consult the ledger") has a
production population of FOUR and the structural answer is stronger than a grep
over them — `from_scan` no longer exists, so the forgetful spelling does not
compile.

**Two non-negotiables, recorded so nobody "fixes" them.** (1) A child run is NOT
charged to the actor's hourly execution budget — the parent's run was budgeted
when it was created, and `budget_precheck` counts `workflow_executions` rows,
which this adds none of (pinned by a DB round trip, not a comment). (2) UNKNOWN
is not zero: the table has a first row, so a count of 0 for a period before
`ChildRunLedger::since()` is *nobody was recording*, and every consumer renders
`null` with the reason rather than `0`. `since()` is deliberately NOT user-scoped
— the question is a deployment fact, and a per-user `MIN` would render UNKNOWN
forever for a user who has legitimately never dispatched a child, turning a real
zero into a permanent "we cannot tell".

**Three implementation facts the code forced, all measured first.** The engine
has NO `execution_id` field (it is a parameter of `run_inner`, and nodes dispatch
concurrently), so `ChildRunSite { execution_id, node_id }` is threaded from the
reactor loop through the five `dispatch_*` handlers — an ENUM with an explicit
`Untracked` variant, not an `Option`, so a sixth handler cannot be added without
the compiler asking; the WRITE still happens in one place. `org_id` was DROPPED
from the RFC's table: the engine has no org handle, and the RLS policy joins
`workflows` for the org exactly as `20260904210000` does, so the column would
have been decorative and wrong. And `status` is CLASSIFIED with check 77's
`output_reports_error`, never `.as_bool()` — a child whose engine returned `Ok`
can still have failed, and the ledger must not disagree with the run about it.

**this change (2026-09-06) — the two smallest consumers say what they measured.** Two report
surfaces asserted a determinate negative for a state the reader could not
represent — checks 74/76/79's class again, in the two places RFC 0012 P1 had
just made representable.

**(B) `get_execution_lineage` contradicted itself in one response.** Its note
read *"This execution has no parent or child executions — it is a standalone
run."* fourteen lines below `child_runs_count`, which since #766 can be ≥ 1.
Both halves were true: the note is a statement about `workflow_executions` ROWS
and was worded as a statement about the RUN, and "standalone" is exactly the
reading the ledger exists to remove. `lineage_note` is now a pure function of
the four facts it may speak about, and the single-node arm is three-valued like
`child_runs_note` beside it: a measured zero, a count with the reason `lineage`
cannot show it, and UNKNOWN for an unreadable or not-yet-started ledger — never
zero, never "standalone". **Latent on this fleet at the time of writing, and the
brief's own observation could not be re-run**: `sub_workflow_runs` holds exactly
ONE row, its parent execution row and both workflow rows were deleted (the
ledger has no FK, by design), so no live execution can currently exhibit
`count ≥ 1` beside that sentence. The defect is pinned by unit test rather than
reproduced live, which is worth saying rather than implying otherwise.

**(D) `get_archive_policy` reported one of the two retention windows and
re-derived it itself.** An execution's readable lifetime is
`ARCHIVE_AFTER_DAYS` (live → archive) PLUS `EXECUTION_RETENTION_DAYS` (archive →
gone), 30 + 30 = **60 days** on the default this deployment runs — kept
deliberately (decision 2026-09-06). The tool rendered the archive tier alone,
so the purge window and the lifetime were invisible in every tool response,
while `EXECUTION_RETENTION_DAYS`' NAME reads like the total it is not.
`docs/configuration-reference.md` explained the 30 + 30 and nothing
machine-readable did. The handler ALSO carried its own
`talos_config::archive_after_days()` read, its own JSON parse and its own
`d > 0` filter — a second implementation of `resolve_retention_windows`, whose
own doc comment claims to be *"the ONLY place that decides which configured
number governs which tier"* — and the two had drifted. It now renders from
`talos_advanced_repository::resolve_retention_policy`, of which
`resolve_retention_windows` is a projection, so the REPORT and the SWEEP cannot
answer differently; every pre-existing key keeps its name and value, and
`set_archive_policy` now states in its response and its description that it
moves ONE of two windows. **The drift shape was narrower than it looked and the
first test for it was green over the mutation** — serde strips the JSON
delimiters, so `'"45"'::jsonb` reaches `as_str()` as `45` and the handler's
`trim_matches('"')` is a no-op there; it bites only on a jsonb string whose
CONTENT carries quote characters (`'"\"45\""'::jsonb` → `"45"`), which the
resolver rejected and the handler accepted. Live population of ANY override on
the reference fleet 2026-09-06: **ZERO** — `system_settings` held no rows at all
— so the drift was latent, and the fix is that there is now one parse rather
than that a live row was wrong. An unreadable setting still REFUSES (#730)
rather than rendering the windows as null: it makes both reported sources wrong
at once, and the one number still producible (the env default) is precisely the
misleading one.

**No lint check was added and `--count` stays 86.** The candidate for (D) —
*"`talos_config::archive_after_days()` may be read only inside the resolver"* —
was measured in both directions before it was written: on pristine `origin/main`
it reports **2** non-test production sites outside `talos-advanced-repository`,
of which **1** is the real defect and **1** is legitimate
(`talos_workflow_validation::history_window_days`, which CAPS a display window
at the archive boundary and decides no retention), i.e. 50% precision over a
population of two, shipping at one-with-a-marker. Below the bar #765's own
numbers set, and the structural answer is already stronger: one `pub` resolver,
the projection above it, and a DB test driving BOTH entry points over the same
rows. For (A) the guard already exists and is check 56 itself; for (B) the
population is one.

**What is NOT guarded, stated rather than implied.** The chokepoint's own
`redact_str` on `error_class` is defence in depth on the `Ok` branch —
`run_scheduler_loop` DLP-scrubs the whole results map on its way out, so
removing the chokepoint's call does NOT turn the DB test red (measured). It is
the ONLY pass on the `Err` branch, where the text is an engine error string that
never met the sanitizer. **No lint check was added and the count stays 86**: the
one write site is a chokepoint the compiler already funnels every caller
through, so a "the ledger must be written" detector would have a population of
ONE and nothing to say.

**2026-09-07 — P3: the ALERTER and the ASSESSOR read the ledger, and the two P2
write sites get a test.** P2 taught the READERS; the two surfaces #762 recorded
as "disclosed, not fixed" and "recorded and NOT changed" are the ones a person
is paged by, and they are closed here.

**The cascading-failure check was blind to a child failing 100% of its runs, and
that was MEASURED before anything was written.** Driving the real reads against
a scratch database: a child with THREE recorded runs inside the check's own
7-day window, ALL FAILED, returns an EMPTY map from
`get_risk_exec_counts_for_ids` while `child_run_stats_since` returns
`runs: 3, failed: 3`. The check took its `None =>` arm, listed the id under
`sub_workflows_unmeasurable` and pushed no risk — indistinguishable from a child
that never ran. The read is now `child_ledger_evidence_since`, which is P2's
readiness read **SPLIT, not copied** (the 30-day entry point is a one-line
projection over it), so the floor arithmetic — read `since()`, clamp the window
to `max(window, floor)`, turn an ABSENT key into a zero-WITH-a-floor — keeps ONE
home while the WINDOW moves to the check's seven days. The decision is the pure
`talos_analytics_repository::cascading_risk::classify_sub_workflow_risk`.

A HYBRID child is judged over the UNION of both tables with the split disclosed
(`measured_over`), because both hold real runs of one workflow and the check
renders ONE `description` per child — two rates under one category would have to
be recombined by the reader with no denominator to do it on.
`LEDGER_MIN_RUNS` gates the CHILD-ONLY population and nothing else: where
execution rows exist the check already had a population it was willing to judge,
so a floor there would be a NEW refusal on a finding that fires today.
`sub_workflows_unmeasurable` changes SHAPE — id strings become objects carrying
`reason`/`child_runs`/`child_runs_failed`/`ledger_since`/`window_start`/`note` —
and every reader was checked (there is exactly one, and none in the frontend).
`UnmeasurableReason` is FOUR-valued: `ledger_not_consulted` is a statement about
the CODE PATH and stays distinct so a wiring regression cannot render as a fact
about the workflow. That distinction earns its keep below.

**"This workflow's SLA-window stats" had FOUR implementations and they
DISAGREED** — check 85's class, and the disagreement moves a verdict. The 5-min
breach monitor's inline SQL and `get_sla_window_stats` (the 15-min degradation
loop) ask the identical question over the identical 24-hour window; only the
first filters `completed_at IS NOT NULL`, so an execution still IN FLIGHT sat in
the second's denominator and never in its numerator, making its success rate
systematically LOWER. One stored threshold row, two loops, opposite verdicts on
one tick. `sla_window::read_sla_window_sources` is now the one read: BOTH
populations in ONE statement, a `UNION ALL` with `GROUP BY ROLLUP(src)` so the
per-source split and the COMBINED percentile come from one pass (a p95 over a
union is not a function of the two sub-p95s and must never be averaged).
`get_sla_window_stats` and its `SlaWindowStats` are DELETED rather than kept as
a projection, for the reason P2 deleted `ReadinessBasis::from_scan`: they
returned `Option`, so a failed read and an empty window were one value, and a
future caller reaching for the convenient name would silently re-acquire the
collapse this change removes. Its one caller reads the new function and handles
three outcomes — **a behaviour change to the 15-min loop, and it is the fix**: the unified definition is the monitor's (runs that
SETTLED in the window), the direction is strictly fewer false success-rate
alerts, and it gains a `user_id` it never had (its docstring called SLA alerting
"platform-wide"; its caller already reads `w.user_id`). `get_latency_percentiles_ms`
and `get_performance_metrics` are deliberately NOT collapsed in: they answer the
latency DISTRIBUTION of SUCCESSFUL runs over a days-window, and folding a failed
run's duration into `duration.p50` would move a number an operator reads without
being asked.

The BREACH DECISION is the pure `decide_sla_breaches`; the loop keeps only
wiring, which is the only thing that makes it testable —
`controller/src/bootstrap/background.rs` is `mod bootstrap` inside `main.rs`, so
no integration test can reach the loop itself (#762 recorded the same fact for
the readiness loop). `LEDGER_MIN_RUNS` gates BOTH metrics when child runs are
the only evidence, and the p95 argument is not weaker than the success-rate one:
a p95 over n=1 IS that one run's latency, so one slow cold start would page
somebody. `not_evaluated` is three-valued, so "no breach" and "could not judge"
are different log lines. The webhook keeps every key AND its per-metric
rendering and gains `sources: {execution_rows, child_runs, child_runs_since,
window_hours}` — counts, a timestamp and an integer, the kinds of value it has
always carried.

**An alerter that cannot measure must say so.** `Err(_) => continue` became a
WARN with `event_kind = "sla_stats_unreadable"` and an error CLASS
(`sla_read_error_class`), once per threshold per tick, full chain at DEBUG; the
same treatment went to the 15-min loop's `_ => continue`, which
`docs/swallowed-results-inventory.md` records as fails-OPEN and which folded
THREE states (read failed / empty window / 1–2 runs) into one silent skip.
**No metric was added, and that is a measurement rather than an omission**: that
function has no `TalosMetrics` handle, so a series would mean threading the
registry into `spawn_late_background_tasks` for a loop that is LATENT on this
fleet. Declined, which means the unreadable-window signal is prose-only and
cannot be alerted on.

**A NULL webhook KILLED the monitor, and the documented configuration is what
produced one.** The threshold row was decoded with `sqlx::Row::get::<String, _>`;
the column is nullable by design (`20260404000001`) and
`set_workflow_sla_threshold` stores NULL for an omitted webhook — its tool
description advertises that as the API-polling configuration. `Row::get` PANICS
on a decode failure and this loop is a spawned task, so ONE such row ended the
SLA monitor for the whole process lifetime, silently. Every column now decodes
through `try_get` in one closure and a bad row skips ITSELF with
`event_kind = "sla_threshold_row_undecodable"`. Also corrected in the same
block: a comment claiming the task "issues per-threshold INSERTs into
`workflow_sla_alerts`". There is no such INSERT and no such table — the 15-min
sibling writes `workflow_alerts` — and a comment asserting a side effect the
code does not have is #732's class.

**`get_workflow_sla_report` measures a child.** `success_rate` is the union
(floored when the ledger is the only evidence), so a workflow that only ever
runs as a sub-workflow stops reporting `not_measurable` however often it ran.
`total_executions` keeps its name's meaning, p50/p95/p99 stay EXECUTION-ONLY and
`duration.population` says so, and `child_runs` appears only when the ledger
contributed or when there are no execution rows at all. Note one disagreement
KEPT and disclosed: this report's denominator includes runs still IN FLIGHT (a
considered decision, pinned by `sla_absence_disclosure_tests`) while the alerter
must not fire on an open run — two different questions, and the response says
which it is answering. The compiler forced all 7 pre-existing tests to state
`child_runs: None` ("not consulted"), which is P2's `from_scan` shape for the
same reason; all 7 pass unchanged.

**Leg C: the two P2 write sites now have a reactor-driven test, and P2's own
mutation was re-run rather than assumed.**
`talos-workflow-engine/tests/child_run_dispatch_recording.rs` drives
`run_with_transport` over `dispatch`, `capability_dispatch`, `agent_loop` and
`react_loop` nodes against a hand-written capturing `ChildRunRecorder` (the
workspace has exactly ONE recorder impl and test-utils has none). Deleting the
`record` call at the tail of `run_dispatched_subworkflow` — P2's M8 — still
SURVIVES the pre-existing engine suite (exit 0, re-measured) and is CAUGHT by
the new binary. Also caught: recording once instead of once per agent-loop
iteration, a `ReActLoop` filed as `agent_loop`, and a `CapabilityDispatch` filed
as `dispatch`. **No LLM stub was needed and that was measured**: the loop body is
the body workflow's graph run through the ordinary `NodeDispatcher`, so a fixed
output controls the iteration count exactly. **One expectation of mine was wrong
and the code was right**: a dispatch child whose terminal MODULE returns
`{"__error": "…"}` is recorded `Completed`, because a dispatch envelope is a
LABEL-KEYED map rather than the collapsed terminal value — and the PARENT node
applies `output_reports_error` to the identical envelope and reaches the
identical answer, which is exactly the invariant the write site claims.

**TWO measured SURVIVORS, both handler-body call sites, and they are not equally
silent.** Setting the SLA report's `child_runs`/`ledger_since` to `None`, and
passing `None` instead of the ledger evidence in the risk check, both leave every
test green — the shape checks 74b and 79b already state as their own limit: the
DB tests drive the repository read, the unit tests drive the pure decision and
the pure renderer, and none can see a call site that computes the right answer
and discards it. The RISK one SELF-DISCLOSES (every entry then reads
`reason: "ledger_not_consulted"` and says so in words, which is why that variant
exists); the REPORT one is SILENT and is left open, with the live read after
deploy as its honest guard — the position #767 and #769 took about their own
call sites. No lint: the population is TWO, and "the handler must pass the read
it just recorded" is a dataflow question, not a textual one.

**A cosmetic defect that reached operator-facing JSON, swept.** The house style
for a long literal is a `\`-continuation, which renders as ONE space because
`\<newline>` skips the newline AND the next line's indentation. Twenty-seven
lines had lost the `\` and kept the indentation, so runs of up to 30 spaces
reached the rendered string — including the cascading check's own note, five of
the SLA report's disclosure strings and four of P2's child-run notes. Measured
workspace-wide with a literal-aware walker: **44 lines**, of which **17 are
legitimate** (aligned `println!` columns, embedded code samples, tests matching
source text, one SQL literal) and 27 were prose. All 27 fixed.
**A lint was BUILT, MEASURED and REJECTED**: the brief's candidate rule (a `\`
continuation followed by ≥2 spaces) describes the CORRECT house style and would
fire everywhere; the rule that does describe the defect still reports the 17
legitimate sites on the fixed tree, i.e. 0% precision at zero and 17 markers on
correct code. Telling prose from an aligned column is a judgement a grep cannot
make. `--count` stays **86**.

**What was measured and NOT changed.** `set_workflow_sla_threshold` still
accepts a row with BOTH thresholds NULL (the invariant lives in the handler and
the tool description, not in a CHECK), and such a row is now evaluated and fires
nothing rather than being a special case. The report's in-flight denominator
stays as it is, disclosed. And the two latency-percentile readers stay separate,
for the reason above.

**2026-09-07 — the report contradicted itself the moment child runs crossed the
floor.** P3 gave `get_workflow_sla_report` a population that spans both tables;
`sample_size_warning` was left keyed on `total_executions == 0`. Two decisions, one
response. Measured live on `pa-quality-judge` (0 execution rows, 3 ledger runs,
floor 3) and reproduced against the real pure renderer: `success_rate.actual: 100.0`,
`met: true`, `child_runs.counted_in_success_rate: true`, and fourteen lines below,
*"No executions at all in the trailing 30 day(s), so nothing about this workflow's
SLA was measured. The success rate, the latency percentiles and the compliance
verdict are all null"* — then, appended, *"The RFC 0012 child-run ledger DOES hold 3
run(s)"*. Below the floor (n = 2) the same sentence is CORRECT, because
`rate_total` is 0 there by construction, which is why nothing looked wrong.

The warning is now derived from `rate_total`, the success-rate block's own
denominator. `sample_n == 0` keeps today's wording **byte-identical**; `sample_n > 0
&& total_executions == 0` gets a new sentence saying the rate WAS measured over N
child runs, that the LATENCY half is what the empty execution table costs, and what
`compliance_status` is — every clause derived from the values actually rendered
(`p99_ms`, `in_compliance`), never asserted, so a caller who passes a p99 with no
execution rows is not told a falsehood about it.

**A second defect of the same keying, found by the same measurement**: `total_u == 0`
short-circuited the whole `else if` chain, so at n = 3 against a 99% target the
STATISTICAL qualification (`min_n_for_meaningful_target` = 100) was unreachable — the
one measured verdict on the surface was rendered with no sufficiency qualification at
all. The sufficiency sentence now has ONE home, a local closure consulted by both
branches, and its denominator is `sample_n`; where that is wider than
`total_executions` the population is NAMED, and where they are equal the sentence is
byte-identical to the pre-fix one (pinned by
`an_execution_only_report_keeps_the_pre_fix_sufficiency_sentence`, which asserts the
whole string).

**The rest of the response was grepped against the basis**, per the brief. Four other
sites read `reads.total == 0`: `ledger_below_floor` (the population decision itself),
the `child_runs` block's emission condition, and the two `population` strings — each
states its OWN population and is correct. `compliance_note` keys on
`in_compliance.is_none()`, i.e. on the basis, and at the floor it correctly reports
the LATENCY component as the unmeasured one. Nothing else changed.

Four mutations, all red: keying the first branch on `total_u == 0` again; keying it
on `child.total == 0`; passing `total_u` to the sufficiency closure; emitting the
wider-population clause unconditionally. **No lint** — the population is one renderer
and the guard is four unit tests over the real pure function; `--count` moves to 87
for leg X1's check only.

## 2026-09-07 — the population behind checks 74 / 76 / 79 / 81: 210 collapsed reads, 110 of them claims

Every prior entry in this family repaired a SITE and named a class. This one
MEASURED the class. `talos-mcp-handlers/src` + `talos-api/src` hold **210**
awaited repository/service reads collapsed into a default, and **110 of them
are CLAIMS** — the default becomes a count, a list, a verdict or a "not found"
that a caller reads and acts on. The full per-site table (file, line, function,
spelling, verdict, the field it feeds) is in the branch's `AGENT_NOTES.md`; the
counts and the decisions are here so nobody re-measures.

**The inventory is statement-aware, and that is why it is bigger than a grep.**
Comment and string content is masked first (so a doc comment quoting the banned
expression cannot self-report — check 73's trap), then the POSTFIX METHOD CHAIN
after each `.await` is walked, so the house style's broken chain is one
statement; a collapse counts only if it precedes any `?`. Per spelling:
`.unwrap_or_default()` **66**, `.unwrap_or(<literal>)` **55**, `.ok()` **32**,
`match … { Err(_)/_ => <default> }` **26**, `if let Ok(..) = ….await` /
`let Ok(..) = … else` **24**, `.unwrap_or_else(…)` **7**.

**Classification: 110 claim / 67 decorative / 32 fail-closed / 1 detector false
positive.** `fail-closed` is dominated by ONE shape —
**15** of the 32 are `is_platform_admin(uid).await.unwrap_or(false)`, which
check 74's opt-out already names as correct. The false positive is
`handle_trigger_workflow_as_actors`, a correct three-way match whose INNER
`actor.status` arm the window matched: stated rather than dropped, because a
detector's limits are worth as much as its findings.

**ELEVEN sites were fixed, in three SHAPES, and 99 claim sites were not.**
Saying so plainly is the point — a fix set chosen as a prefix of a list teaches
nothing, and half-fixing a class to satisfy a gate is how the glob got its
blind spot.

* **A refusal that asserts NON-EXISTENCE on a read that failed.**
  `actor::resolve_actor_via_repo` is the ownership gate behind **20+** actor
  tools and its `Err(_)` arm rendered *"Actor not found or access denied"* —
  false on both clauses while the database is the broken thing. The correct
  three-way shape was already in the same crate
  (`evaluation::ensure_actor_owner` splits `Err(_) => "actor ownership check
  failed"`), so this is a rule that failed to REPLICATE, exactly as check 79
  records about the four integration handlers.
  `knowledge_graph::require_owned_actor` is the byte-identical twin.
  `ml::require_dataset_owner` needed the CALLEE fixed first — check 79's leg (b)
  verbatim: `DatasetService::dataset_tenancy` folds absence INTO `Err`, so
  `Ok(None)` was structurally unreachable and no call-site split was possible.
  `lookup_dataset_tenancy` is the three-way read; `dataset_tenancy` stays as a
  documented FLATTENING projection because its eight in-crate callers propagate
  with `?`, i.e. FAIL rather than claim.
* **A swallowed read driving a DESTRUCTIVE or inventory decision.**
  `handle_cleanup_module_versions` read `refs.is_empty()` as "nothing points at
  this module → deletable", and its reference read was `.unwrap_or_default()` —
  so with `dry_run: false` an IRREVERSIBLE delete was decided by a query that
  did not answer (check 86's shape on a path that deletes rather than
  recommends). Held-back modules are excluded from `deletable` AND disclosed
  under `unknown_references`, with the sentence saying why its count is short.
  `handle_batch_delete_modules`'s classification default is fail-closed for the
  DELETE and NOT for the REPORT — it told the caller, by name, that each of
  their modules does not exist — and now refuses. `handle_list_templates` /
  `handle_list_modules` refuse too: an empty listing is the premise of every
  next step an operator takes, and there is no partial answer to give.
* **A COUNT or LIST rendered as a report field.**
  `handle_get_workflow_summary` answered a database failure with the four most
  reassuring numbers it can produce — `total: 0`, `versions: 0`,
  `active_schedules: 0`, `active_webhooks: 0`, i.e. *never run, never published,
  nothing triggers it*, which is the reading an operator uses to decide a
  workflow is safe to retire. **That handler already had a DOCUMENTED case of
  this swallow hiding a real bug**: `get_workflow_schedule_count`'s own comment
  records that the query named a column that does not exist (`is_active` vs
  `is_enabled`) and *"handler `unwrap_or(0)` swallowed the column-not-found
  error and `get_workflow_summary` reported `active_schedules: 0` for every
  workflow, including ones with active schedules"* — the QUERY was fixed in May
  2026 and the SWALLOW was left in place, the sixth local repair of a class with
  no population sweep behind it. `handle_list_executions` fell back to
  `rows.len()` — the PAGE LENGTH — so an unreadable count over 4 000 executions
  rendered `total: 20, has_more: false` and a caller paging on that envelope
  stops at the first page believing it has everything.
  `handle_get_catalog_status` is a DIFF, so an unreadable `list_catalog_rows`
  put every disk template in `on_disk_not_in_db` and emitted *"restart the
  controller to seed"* — specific, actionable, wrong advice about a healthy
  catalog. `handle_get_execution_replay_chain`'s empty `ancestors` /
  `descendants` are the same determinate negatives #771 removed from
  `get_execution_lineage`'s "standalone run" sentence one tool over.

**Three of the eleven are pinned by a DB test that drives the REAL
`McpState` and the production `dispatch`**
(`controller/tests/swallowed_read_disclosure_tests`, CTRL_TESTS per check 64b —
it is a `mod common` binary). The failure mechanism is package 22's: the
RELATION the read names is DROPPED in the per-test isolated database, so the
statement cannot run. It builds a real state rather than a stand-in because the
defect is what the handler BODY renders — checks 74b and 79b both state, as
their own limit, that a guard at the READ cannot see an answer classified
correctly and discarded further down. Every test carries its CONTROL in the same
run (a fresh user really does have zero modules; a workflow with no schedules
really does report `0`; an actor that is genuinely absent keeps the not-found
sentence), because a healthy response must stay byte-identical and only a
degraded one may change shape. Three mutations reinstating main's expressions
are all RED — and M2's response was literally `{"count": 0, "modules": []}` with
the view DROPPED.

**The lint candidate was BUILT, MEASURED and REJECTED — `--count` stays 87.**
Widening check 74 from its name glob to EVERY handler for
`.unwrap_or_default()` / `.unwrap_or(Vec::new())` / `.unwrap_or(0)` over an
awaited read reports **73 on pristine main, 61 of them claims — 83.6 %
precision**, which sits between check 74's #730 group (81.8 %) and its
2026-09-02 group (94.1 %). Precision is not the problem. It would ship at
**62** on this tree, i.e. as a ratchet with a baseline, and "do NOT re-add a
baseline" is check 52's own rule (#760: *"a check cannot ship at 21"*). The
twelve false positives are the same shape every time — a display name or a
suggestion list beside untouched counts. **What ships instead costs no check
number: sub-leg 74b covers the three repaired report handlers AUTOMATICALLY**,
because its scope is DERIVED ("any function constructing a `Readings`") and they
enrolled themselves by adopting the ledger. That is not a theoretical
convenience — **74b fired on the first lint run after the fixes**, at
`handle_get_catalog_status`'s disk scan, where a `JoinError` defaulted to an
EMPTY template list that reads as "this image carries no catalog templates". A
filesystem read inside a catalog tool is exactly what a hand-maintained glob
would never have looked at. The way to extend the coverage is to fix a handler,
not to widen a regex.

**Two fail-OPEN gates are RECORDED and not fixed**, and they outrank the
remaining report sites for whoever takes the next pass:
`search::handle_tag_workflow` skips the 100-tag cap when the count read fails,
and `sandbox::handle_run_sandbox` skips the LINT step entirely on
`if let Ok(lint_errors)`. And `analytics::handle_get_workflow_dependencies_list`
(`schedules`, `webhooks`) is deliberately untouched: it is the site the sibling
PR #775 fixes.

### The whitespace-run artefact, and why no lint guards it

Four operator-facing string literals carried mid-sentence runs of up to 22
spaces — a `\`-continuation that lost its `\` and kept the indentation. All
four are from #771's dispatch-attempt work and all say the same thing in four
places: an audit-ledger WARN read during a tamper investigation, a Prometheus
**HELP** string, and two `security_audit` disclosure sentences. A line grep
cannot see the shape (the run spans the continuation join), so the measurement
used a literal-aware walker: **9 literals with a ≥5-space run on main, 3 SQL
column alignments, 6 prose, 4 of them defects; 0 defects after.** The two
surviving prose hits are the CLI's aligned help columns and are correct.

**Both candidate guards were measured and rejected.** A grep scoped to literals
with no SQL keyword reports 6 on main (66.7 % precision) and **2 on the fixed
tree**, both legitimate — it would ship above zero with markers on correct code,
and adding a prose-punctuation clause does not separate an aligned help column
from a sentence (`"… List the DB worker-identity registry."` has a full stop).
A render-time collapse at `mcp_text`'s JSON boundary is rejected on two grounds,
one of them measured: it hides the defect rather than preventing it (the source
literal stays wrong and the next reader copies it), and **it would have covered
two of these four at most** — the Prometheus HELP text and the tracing WARN
never pass through `mcp_text`.

### `remove_member` refused every caller, and that is why the mutation survived

The brief for this package recorded a redundant last-owner arm in
`talos_organizations::remove_member` and asked for the reachability enumerated.
It is enumerable and the second arm was DEAD: `check_org_access(.., Admin)`
admits only Admin or Owner; the rank rule refuses a caller below the target and
`Owner` is the maximum, so a target of Owner implies a caller of Owner; two
DIFFERENT owner rows make `owner_count >= 2`. So the guard is reachable only
when `caller_id == user_id`, which the first arm already answers — the second
was a strict subset behind a `return`.

**But the enumeration is not why the mutation survived.** Writing the test for
the surviving arm turned it RED with `Failed to count owners`:

    SELECT COUNT(*) FROM organization_members
    WHERE org_id = $1 AND role = 'owner' FOR UPDATE
    -- ERROR:  FOR UPDATE is not allowed with aggregate functions

Postgres refuses the statement outright, so **`remove_member` failed for EVERY
caller and every target** — the member-removal path has been entirely
non-functional since MCP-996 added the TOCTOU hardening in May 2026, and
NEITHER last-owner arm was ever reachable. No test could have distinguished the
arms however it was written. The same statement appears a second time in
`update_member_role`'s demotion guard, where it fires only when demoting an
Owner. Both now put the aggregate OUTSIDE the locking subquery
(`SELECT COUNT(*) FROM (SELECT 1 … FOR UPDATE) locked_owners`), which takes the
same row locks. **LATENT on this deployment**: the live database holds 1
`organization_members` row and 0 non-personal organizations.
`organization_tests::the_sole_owner_cannot_remove_themselves` asserts the
MESSAGE and not merely the refusal — asserting `is_err()` is precisely what let
the dead arm stand in for the live one — with a control proving the guard keys
on the owner COUNT rather than on self-removal.

### A harness helper that had never once executed

`controller/tests/common::create_test_organization` issued
`INSERT INTO organizations (name) VALUES ($1) RETURNING id`, omitting **two**
NOT NULL columns (`slug` and `owner_id`), so it failed on every call. Nothing
noticed because its only caller, `create_authenticated_org_client`, had zero
callers: three helpers deep, all dead, so the first test to reach for the
harness would have failed on the harness rather than on its subject. It now
routes through the production `OrganizationService::create_org` (the Testing
Conventions rule — and it had drifted), `add_user_to_organization` became an
UPSERT because `create_org` already inserts the owner's membership row, and
`api_auth_integration_test::org_scoped_client_helper_actually_provisions_an_org`
drives the chain end to end. Reinstating main's helper body is RED.

## The verifier that could never read the ledger it verified (#767)

**Measured live 2026-09-06, and the shape is "presence is not function" at the
identity layer.** The WORM audit bucket has one job that needs `PutObject` and
another that needs `ListBucket`+`GetObject`, and until this change ONE identity
served both. `build_audit_s3_client` resolved credentials through
`aws_config::load_defaults` — the `AWS_*` chain — for the write path AND the
read path, and on every deployment of this platform `AWS_*` is
`MINIO_CONTROLLER_USER`, whose policy is `audit_write_only` (`s3:PutObject` and
nothing else). So: `mc ls` under those credentials answers **Access Denied**;
the bucket held **48,946** execution prefixes written since 2026-07-08 with the
newest minutes old (the WRITER works); the hourly sweep logged **37**
`audit_chain_verification_errored` lines in one hour and the controller's ENTIRE
history contained **zero** `audit_chain_verification_failed` and zero verified
chains. Chain verification had never once succeeded.

**Why nothing said so.** `record_chain_verification_outcome` incremented
`talos_audit_verification_failures_total{stage="chain"}` only on `Ok(report)`
with breaks; the `Err` arm incremented NOTHING and logged one WARN. The single
alert on that series names the gap in its own comment. `security_audit` had no
chain check at all — `audit_event_signing` signs a probe in memory,
`audit_immutability_triggers` counts `pg_trigger` rows. And the log said
`error = list_objects_v2 failed for <exec>/: service error`, because `Display`
on an `SdkError` drops the S3 code: AccessDenied, NoSuchBucket and a reset
connection are the same four words. **And the identity was only half of it** —
the sweep was also naming an id space the writer has never used, which the
population section below establishes with a live positive control.

**The two identities are now separate and the writer stays write-only.** The
verifier is `MINIO_VERIFIER_USER` under a new `audit_read_only` policy
(`s3:ListBucket` on the bucket + `s3:GetObject` on its objects; NO Put, NO
Delete), reaching the controller as `AUDIT_VERIFIER_ACCESS_KEY_ID` /
`AUDIT_VERIFIER_SECRET_ACCESS_KEY`. `talos_audit_ledger::verifier`
builds that client from an EXPLICIT `Credentials` provider with **no
`load_defaults` on the path**, so there is no environment chain for the writer's
key to be picked up from. Absent verifier credentials are `VerifierClient::
NoCredentials` — three-valued against `NoEndpoint`, because "there is no WORM
store here" and "there is one and nothing can read it" are different findings —
and the sweep then refuses to start with one ERROR rather than silently retrying
a key that cannot work. **Do not widen the writer's policy to "fix"
verification**: a writer that can also list and get is a writer that can survey
and target what it wrote.

**Failure is CLASSIFIED, and the classification decides the sweep's shape.**
`ChainVerifyErrorKind::{AccessDenied, NoSuchBucket, NotFound, Transport, Other,
NoCredentials}`, derived from the SDK's typed `ProvideErrorMetadata::code`
rather than from the rendered string, with the full chain captured via
`DisplayErrorContext`. `AccessDenied`/`NoSuchBucket`/`NoCredentials` are
DEPLOYMENT-WIDE facts — one identity, one bucket — so the 2nd..Nth jobs in a
sweep cannot answer differently; the sweep ABORTS on the first, records
`ChainSweepStats::aborted`, and emits ONE `audit_chain_sweep_aborted` ERROR
instead of up to `MAX_JOBS_PER_SWEEP` identical WARNs. `NotFound`/`Transport` are per-object and do NOT
abort. The abort flag is a CLAIM ABOUT COVERAGE in the same family as
`cap_hit`: after an abort `failed == 0 && errored == 1` is true and means
nothing.

**Instruments.** `talos_audit_chain_unverifiable_total{reason}` (all six values
PRE-SEEDED at 0 — `increase(...) > 0` over an absent series matches nothing, which
is exactly how this stayed quiet) is deliberately a SEPARATE series from
`talos_audit_verification_failures_total`: unverifiable is not verified-bad
(#578), and folding an object-store blip into the CRITICAL tamper alert would
train operators to ignore it. Two GAUGES, and they answer different questions
that disagreed for two months on this stack:
`talos_audit_chain_last_verified_ok_timestamp_seconds` (the control works) and
`talos_audit_chain_sweep_timestamp_seconds` (the loop is alive). The first is
deliberately NOT pre-seeded — a zero seed reads as 1970 and would fire every
staleness rule on a healthy cold boot — so `TalosAuditChainNeverVerified`
carries an explicit `absent()` arm and is GATED on the sweep having run, so a
deployment with no object store is not permanently red.
`TalosAuditChainUnverifiable` is `warning`, not critical: it says the CONTROL is
not working, not that the ledger is bad.

**`security_audit` gains `audit_chain_verification` (`control`, `round_trip`),
WEIGHT 0 — and the zero is argued from scratch rather than borrowed.** Of
`write_ceiling_enforcement`'s three reasons exactly ONE applies: the grade bands
are ABSOLUTE against a 100-point total (`weights_sum_to_max_score`, and
`MAX_SCORE`'s own doc block leans on a dev stack topping out at exactly
`GRADE_A`), so an eleventh weighted check would re-grade every deployment and
make every score recorded before today incomparable. Reason 1 ("default-OFF by
design") does NOT apply — the sweep defaults ON. Reason 3 ("conditional") does
NOT apply — where a ledger is written and never verified the compliance artifact
is unbacked unconditionally. The zero is not decorative: an unverifiable control
and a broken chain both render `Status::Fail` with CRITICAL, so both land in
`status_counts.fail` and in `recommendation_for`, which names failing checks by
name. The check runs the REAL verifier on the most recent terminal execution
outside the settle window (`CHAIN_SETTLE_SECS`, now shared with the sweep so the
two grade the same population), increments no counter (an operator re-running
the audit must not move a series an alert fires on), and renders five outcomes
including `NothingToVerify` split three-valued so a failed candidate query never
reads as "there is nothing to verify".

**The chart NEVER provisioned any of this, and that is fixed here too.**
`grep -rn "mc admin" deploy/` matched nothing: the MinIO StatefulSet set only
ROOT credentials, `install.sh` generated a controller user+password no `mc`
invocation ever created, and README.md called it a "least-privilege write-only
user". On a k3s deploy the bucket would not exist and the writer's key would
name no principal — the ledger dark end to end. The new `minio-provisioning`
Job (post-install/post-upgrade hook, idempotent) creates the bucket and BOTH
identities, mirroring the compose recipe. This remains **LATENT**: there is no
production environment (memory `no_production_environment`), so nothing was
observed failing this way — stated rather than dressed up.

**What was measured and NOT changed.** The compose `minio-init` container
receives `MINIO_WORKER_USER`/`_PASSWORD` and has never created that user —
`mc admin user list` on the live MinIO returns exactly ONE user. Dead env, a
separate finding, and the worker does not touch S3 (it publishes to
`talos.audit.ledger`). **CLOSED 2026-09-07** — see "A credential for a
principal that does not exist" below; the pair is gone from compose, the chart,
`values.yaml`, `install.sh`, `.env.example` and both `.env` generators, and
`mc admin user list` now returns exactly TWO users, neither of them a
worker. The GraphQL `verifyAuditChain` error message is generic
and correctly directed and is unchanged; what DID change is that it now builds
its client from the verifier identity, so the operator's on-demand path was
broken by the same defect and is fixed by the same line.

**No lint check was added and `--count` stays 86.** The obvious guard — "the
verifier must not use the writer's credentials" — has a population of ONE, which
is the bar this repo does not ship at (#765's own numbers), and the structural
answer is already stronger: a distinct env name, an explicit credentials
provider with no `load_defaults` on the path, and
`verifier_client_signs_with_the_explicit_credentials`, which drives a real
`list_objects_v2` at a one-shot TCP listener and reads the access key id out of
the SigV4 `Authorization` header the SDK actually put on the wire. That test
exists because `aws_sdk_s3::Config::credentials_provider()` is DEPRECATED and
returns `None` unconditionally, so the obvious config-readback assertion would
have passed vacuously against a client carrying no credentials at all — the
exact mutation it is there to catch.

**The fix would have made the report WORSE, and that was found by driving the
real verifier against the live store rather than by reasoning.** With
read-capable credentials the SAME execution the writer's key was denied came
back `ok=true, total_events=0` — because `verify_chain` over an EMPTY event set
answers `ok == true` (there are no gaps, no broken links and no bad signatures
in nothing). Then the id-space, measured in BOTH directions: **200 of 200**
recent ledger prefixes are `module_executions.id` and **0 of 200** are
`workflow_executions.id`, live table AND archive; **0 of 200** recent
`workflow_executions.id` appear as a prefix; **34 of 34** terminal executions
inside the sweep's own 2 h window have an empty prefix — against a WRITER that
is healthy (2,686 objects in 2 days, 49,239 / 23 MiB total). The writer keys on
the `execution_id` carried by the audit EVENT, which is the module execution;
`run_chain_verification_sweep` enumerated `workflow_executions`. So repairing
the identity alone would have turned 37 loud WARNs into 37 silent
`verified_ok`, stamped the new "last verified ok" gauge, rendered
`security_audit` PASS and kept `TalosAuditChainNeverVerified` quiet — strictly
worse than the AccessDenied, which at least logged. `ChainVerifyErrorKind::
EmptyChain` (7th reason, seeded, does NOT abort — one execution may legitimately
emit no events and the VOLUME is the finding), `ChainSweepStats::empty` counted
separately from `verified_ok`, no gauge stamp on an empty read, and the check
renders `Warn`/`NotVerified` saying *the identity is working and the prefix is
empty* so nobody chases a permission fault that no longer exists. Note
`verified_ok`'s meaning moved (it now requires ≥1 event).

**And the POPULATION is fixed in the same change, because a verifier that
enumerates an id space the writer never uses verifies nothing forever.** An
honest `empty` on 100% of rows is a report nobody can act on and a control that
still does not work — the gate-that-doesn't-gate class (#624, checks 64/65) one
level up. **The binding was ESTABLISHED, not guessed**, and the guess was wrong:
`worker/src/main.rs` builds the worker's `execution_context` as
`(req.workflow_execution_id, req.job_id, req.module_uri)`, `runtime.rs` turns
the first two into `ExecutionLedger::new(workflow_id, execution_id)`, and
`job_id` IS `module_executions.id` (`engine_dispatch_single.rs` mints it and
passes it as `ExecutionStartedContext { id: job_id, .. }`, the primary key of
the row it inserts). So the genesis pair is
`(module_executions.workflow_execution_id, module_executions.id)` — the FIRST
half is a workflow EXECUTION id, not `workflows.id`, even though the ledger
field is named `workflow_id`. **The live positive control settles it**, driving
the real `verify_execution_chain` against the live MinIO with read-capable
credentials (one temporary example binary, since deleted): the established pair
returns `ok=true total_events=1 breaks=0 sigs_checked=true` (6 of 6 sampled, 50
of 50 in a wider run); the pair a reader would GUESS from the field name
(`workflows.id`) returns `ok=false breaks=1`, a genesis mismatch on a healthy
chain; and the pre-fix sweep's own shape returns `ok=true total_events=0`.
`ChainVerifyErrorKind::EmptyChain` was therefore load-bearing for one day and is
kept: an empty prefix stays a distinct outcome whichever id space is
enumerated — but its EXPECTED frequency has inverted, and the prose says so.
Sampled 200 recent settled module executions: **0 have an empty prefix**, so a
non-zero `empty` is now a real per-job finding (the worker emitted nothing, or
its batch never reached the store) rather than the whole population.

**The ledger is keyed per JOB; the operator asks per RUN; both grains are
reported and neither is folded into the other.** `run_chain_verification_sweep`
enumerates `module_executions` through ONE query with NO join — that table
carries both halves of the pair, so the join a reader expects is not batched
away, it is unnecessary — and `roll_up_by_workflow_execution` lifts the per-job
outcomes to workflow executions with WORST OUTCOME WINS (`Failed > Errored >
Empty > VerifiedOk`, the `Ord` derive on `JobChainOutcome` IS the precedence).
One broken chain among a run's four jobs makes that run's audit trail broken,
not three-quarters clean. The summary line, the `security_audit` sweep note and
the admin `verifyAuditChain` query all carry both numbers plus
`LEDGER_KEY_SPACE`, so nobody has to guess which table an id belongs to.
`security_audit`'s round-trip check picks the most recent settled MODULE
execution and names both ids and the key space in its detail.
**`verifyAuditChain` was the THIRD surface with this defect** and was doubly
wrong — it used the caller's `workflow_executions.id` as the S3 prefix AND
`workflows.id` as the genesis half, i.e. both of the two negative controls
above. It now resolves the execution to its jobs, verifies each, and returns
per-job reports under an aggregate whose `ok` requires **at least one** verified
chain: `jobs.iter().all(..)` over an empty iterator is `true`, which is this
whole change's defect in one line.

**Cost and cap, measured rather than assumed.** The population is ~3.3x larger:
101 module executions in the sweep's own 2 h window against 32 workflow
executions, peak 150 vs 45 per 2 h bucket over 7 days, 1,342/day. A verification
is one `list_objects_v2` + one `get_object`; 50 real ones against the live store
took 1.6 s wall including process start (~30 ms each). `MAX_JOBS_PER_SWEEP` moves
500 → **2000**, restoring the ~11x headroom the old cap had and costing ~60 s of
an HOURLY tick at the cap. `cap_hit` is exactly as honest as before: the sweep
keeps no cursor, so rows the cap drops age out of the sliding window and no
later pass picks them up.

**What was measured and NOT changed.** `module_executions.workflow_execution_id`
is NULLABLE and a row without one has no genesis pair, so it cannot be verified —
measured at **0 of 48,577 rows platform-wide**, i.e. LATENT, and stated as such
rather than dressed up. It is COUNTED (`ChainSweepStats::unbound`, disclosed in
the summary and in the sweep note) rather than filtered out of sight, and that
decision needed a structural move: with the increment inside the S3-dependent
sweep loop, deleting it left **all 45 ledger tests and all 84 security-audit
tests green** (measured, not inferred). `partition_sweep_rows` returns
`(targets, unbound)` so the caller cannot obtain the targets without the count it
must disclose, and the mutation now fails. The same discipline put the sweep's
enumeration statement in `enumerate_sweep_jobs`: a DB test drives the EXACT
statement the sweep issues, because the defect was a SELECT naming the wrong
table and no amount of testing the verification logic could see it. And the
sweep still runs on the BARE POOL — a platform-wide system task with no caller
and no tenant to scope to; a tenant-scoped tx would verify one tenant's chains
and silently certify the rest.

**Adjacent fix in the same change (#765's class, one sentence over).**
`describe_disabled_retry_protection`'s zero-ceiling arm said *"even its single
first attempt can outrun the budget"* — the TRUNCATED wording — for BOTH shapes
a zero ceiling can take, because `max_retries_within_budget` returns `Some(0)`
whenever the retries=0 sequence is not `AttemptFit::Full`, which is true of a
CLAMPED single attempt too. Measured on the reference fleet 2026-09-06: that arm
fires on exactly TWO nodes and BOTH are clamped, so **2 of 2 live occurrences
were false** — and both nodes emitted the sibling `attempt-window-clamped`
finding saying *"Every configured attempt starts, but attempt 1 is CLAMPED to
118s of the 125s"* in the SAME `validate_workflow` response, five lines apart.
`NodeRetryBudget` now carries the ceiling and the single-attempt fit as one
value from one function, so a caller cannot supply a pair that disagrees, and
`zero_ceiling_reason()` has ONE home — `get_workflow_risk_assessment` carried
its own copy of the truncated wording in its `recommendation` string and now
reads the same clause.

**2026-09-07 — the first sweep that ever ran called an identical redelivery
"possible tampering".** #767 gave the verifier an identity that can read; the
FIRST completed pass then reported `jobs_scanned=102 jobs_verified_ok=101
jobs_failed=1`, and the one failure was a prefix holding ONE object whose two
lines were BYTE-IDENTICAL — same `sequence_num` 1, same `previous_hash`, same
`hash`, same `hmac_signature`, same `timestamp` — logged at ERROR as *"possible
tampering, deletion, reorder, or corruption"* and incrementing
`talos_audit_verification_failures_total{stage="chain"}`, the series whose HELP
text says "positive tamper/corruption evidence" and whose whole value is that
its steady state is 0. A false CRITICAL on the one control that exists to raise
a true one (check 69's class, on the audit control).

**Two duplicate kinds, and only one says anything about integrity.**
`verify_chain` sorted by `sequence_num` and reported `DuplicateSequence`
whenever two adjacent events shared one, WITHOUT comparing their content. Now:
BYTE-IDENTICAL (equal recomputed hash AND equal signature — hash covers every
field but the signature, so the pair is equal iff the events are) is
`ChainBreak::DuplicateDelivery`, which is REPORTED and does not clear `ok`;
CONFLICTING content stays `DuplicateSequence`, still tamper evidence, still
CRITICAL. `ChainBreak::is_tamper_evidence` is the one predicate `ok` is computed
from, so a NEW variant must decide which it is at the point it is added instead
of inheriting "break". Chain continuity was ALREADY computed over the deduped
sequence — the pre-existing `continue` left `prev_hash` and `expected_seq`
untouched — and that is recorded as a no-op rather than claimed as a fix.
`anchor_verdict` now dedupes too: without it one identical redelivery produced
TWO hard failures (`CountMismatch`, because the anchor commits 1 and the
verifier counted 2; and a phantom `MultipleAnchors`).

**The writer/verifier split is asymmetric ON PURPOSE.** `process_batch` drops an
exact duplicate that shares a batch (`talos_audit_ledger::batch_dedupe`,
`talos_audit_ledger_duplicate_deliveries_total{scope="batch"}`, one INFO line
per batch, every dropped copy still ACKed — an unacked message is redelivered
forever). It CANNOT dedupe across batches, because that means LISTING and
READING the execution's prefix and the ledger writer's S3 identity is
**write-only by design** — the read-only verifier is a separate credential
precisely so a compromised writer cannot survey what it wrote. **Do not widen
it.** Cross-batch copies are classified at the verifier instead, where the
read-only identity already belongs.

**The cause was the PRODUCER, and the population says so.** Measured over the
whole bucket 2026-09-07 (49,720 objects / 49,461 prefixes): **196 prefixes
(0.40 %) carried more than one terminal anchor — 35 byte-identical, 161
CONFLICTING**. So the verifier classification covers 18 % of the historical
population and the producer fix covers all of it. Mechanism, from the worker log
(one `Received job`, one `Job completed`, **two** `wasm-execution` spans):
`execute_job_with_full_features`' retry loop called the internal attempt
function up to `RetryPolicy::max_attempts + 1 = 4` times, and EACH attempt built
a fresh `ExecutionLedger::new(workflow_id, exec_id)` and appended its own
terminal anchor — every attempt restarting at `current_sequence = 0` and at the
deterministic genesis hash, so every attempt emitted an `execution_complete`
event claiming `sequence_num` 1. `AuditEvent::timestamp` is WHOLE SECONDS, so
two attempts inside one second are byte-identical and two either side of a
second boundary are not: **a second boundary is the whole difference between the
35 and the 161**, not any property of the transport. The object size classes
match the attempt ceiling exactly (2, 3 and 4 copies; none above 4 in the recent
population).

Now: ONE ledger per JOB, minted above the retry loop and shared by every
attempt, so the chain is one monotonic sequence over the whole job; and ONE
anchor, appended by `seal_job_audit_chain` after the last attempt. The retry
loop's four terminal exits were wrapped in a labelled block so the anchor has
exactly ONE emission site — a helper called at each of four exits is one
forgotten call site away from the defect being reintroduced. The anchor is still
EARNED, not automatic: `anchor_eligible` is set at the same point the inline
anchor used to be appended (below the wall-clock timeout's `?`), so a job killed
by the wall clock still earns nothing and keeps the deliberately-soft
`Unanchored` verdict.

**What #769 did NOT close, and it is 150 of the 196 prefixes.** The anchor is one
per DISPATCH, not one per JOB-ID. A controller-level retry re-dispatches the SAME
`job_id` (`talos-workflow-engine-nats::execute_job_with_retry`, whose own doc
notes the worker re-sees it), and each re-dispatch is a fresh
`execute_job_with_full_features` call with a fresh ledger — which is why the
ledger holds prefixes with far more copies than the in-worker ceiling of 4 (one
has ELEVEN objects written 5 s apart across 55 s). Reconstructing a prior
dispatch's ledger needs persisted state the credential-free worker cannot read.
That is the next entry.

## A re-dispatched job is a second chain, and the wire says so

**`JobRequest.dispatch_attempt` — the partition key a credential-free worker
cannot derive.** #769 fixed the in-WORKER retry (one ledger per job). The
remainder it recorded is the CONTROLLER re-dispatching the same `job_id`: each
re-dispatch is a fresh worker job with a fresh ledger, so two dispatches write
two chains that both start at `sequence_num` 1 against the same genesis, under
one S3 prefix. `verify_chain` sorted by `sequence_num` alone and had no key to
tell them apart, so it reported `DuplicateSequence` — positive tamper evidence,
ERROR, `talos_audit_verification_failures_total{stage="chain"}` — every time a
controller retry followed a completed-but-unanswered attempt. A worker with no
credentials cannot know it is a re-dispatch unless the controller tells it.

**Measured on the live bucket 2026-09-07** (49,863 objects / 49,604 prefixes):
**150 prefixes hold more than one object** (111×2, 23×3, 5×4, 3×5, 1×7, 1×8,
1×10, 2×11, 3×12) plus **41 single-object prefixes at 960 B under a `1_1_` key**
(two seq-1 events in one object), i.e. ~191, consistent with #769's 196. The
largest are provably controller retries, not in-worker ones: the 12-object
prefix's `workflow_executions` row carries `node_started` + **two
`node_retrying`** + `node_failed`, i.e. **3 controller dispatches × 4 in-worker
attempts = exactly 12 objects**, and 11–12 copies exceed the worker's own
`RetryPolicy::default().max_attempts = 3` ceiling. Rate: ~1,300
`module_executions`/day against 0–4 `node_retrying` events/day.

**#769's mechanism sentence was wrong and the correction matters**: this is not
"after a timeout". `execute_job_with_retry`'s `Err(_timeout)` arm RETURNS; the
two arms that loop are an application-level failure and a NATS delivery/reply
error. A reader sent to the timeout branch finds nothing.

**The design.** `JobRequest.dispatch_attempt: u32`, `#[serde(default,
skip_serializing_if)]`, appended to `signing_payload` as `:attempt=<n>` ONLY when
non-zero and at the very END — so an all-default request is byte-identical on the
wire AND in its MAC (pinned by the unchanged
`job_request_signature_snapshot` hex plus a NEW non-default snapshot with its own
JSON + MAC). `AuditEvent.dispatch_attempt` follows the same idiom into
`calculate_hash`, so an attempt-0 event's hash and HMAC are byte-for-byte what
they were and **every object already in the bucket keeps verifying** —
`attempt_zero_event_hash_and_hmac_are_pinned` locks the literals, and the formula
was additionally re-derived by an INDEPENDENT Python implementation against a real
bucket object (stored `hash` and `previous_hash` both reproduced exactly), because
a fixture that pins the code against the code cannot see a both-sides drift.
`verify_chain` PARTITIONS by attempt and verifies each partition as its own chain
**from the same genesis** — the attempt is a partition key, NEVER a genesis
input, so an old chain and a new one are verified by one rule — and
`verify_chain_anchored` partitions its anchor verdict the same way (two attempts
carry two terminal anchors, which as one set read `MultipleAnchors`, a HARD
failure, on a retried job). Within one attempt `DuplicateDelivery` and
`DuplicateSequence` keep #769's meanings exactly; the CONTROL test proves a
conflicting pair at ONE attempt still fails.

**ONE stamping site, and that is structural rather than tidy.**
`resign_payload_for_retry` sets the attempt before signing. Both call sites sit
inside `if let Some(key) = worker_shared_key`, so a deployment with no WSK
re-sends the ORIGINAL bytes — and that path **cannot produce a second chain at
all**: `req.verify_dispatch` (nonce-replay included) runs in the worker ABOVE the
ledger, so a replayed nonce fails before `execute_job_with_full_features` is
reached. Every path that can write a second chain re-signs, and that is exactly
the path that stamps.

**Deploy ordering — measured in both directions, and the two are NOT symmetric.
WORKERS ROLL FIRST OR TOGETHER**, the same rule the envelope-seal note carries,
and the first draft of this paragraph got it backwards before the test was
written. **Old controller + new workers is completely inert**: nothing stamps
anything, every message is attempt 0, every byte identical. **New controller +
old workers is safe for FIRST dispatches and refuses RETRIES.** Attempt 0 appends
nothing, so an ordinary dispatch is byte-identical and an old worker verifies it
exactly as before. A RETRY, though, is signed by the new controller over a
payload ending `:attempt=1`, and an old worker's `signing_payload` cannot produce
that segment — it does not know the field — so the two MACs differ and the old
worker REFUSES the retry. Pinned by
`an_old_worker_refuses_a_new_controllers_retry_but_accepts_its_first_dispatch`,
which rebuilds the pre-field payload and asserts the signatures diverge (if they
matched, binding the attempt would be a no-op). This is **fail-CLOSED and
bounded**: the failure is a refused retry of an already-failing job, not a
mis-verified one, and it lasts only for the width of the rollout — measured
0–4 `node_retrying` events/day on the reference fleet. Roll workers first and it
never arises.

**Disclosed, never silent.** The sweep counts `ChainSweepStats::multi_attempt`
and logs `jobs_with_multiple_attempts`; `security_audit`'s round-trip check names
the attempt count on the chain it probed (because "4 events, verified" and "two
dispatches of two" otherwise render identically — the same argument the
`duplicate_deliveries` disclosure makes one axis over) and the sweep note carries
the fleet count; the GraphQL job report gains `dispatchAttempts` and the
aggregate `jobsWithMultipleAttempts`; `talos_audit_chain_multi_attempt_jobs_total`
is pre-seeded at 0. **Nothing alerts on it** — a re-dispatch is the platform
working as designed, and an alert here would train operators to ignore the one
control that raises a true finding, which is the defect this change removes.

**What is NOT closed, stated rather than implied.** (a) **Historical prefixes
stay CONFLICTING.** Both copies carry no attempt field, so they partition into
ONE attempt and `DuplicateSequence` is the correct answer for them — the fix is
forward-only. They age out of the sweep's 2 h window; the ~191 already in the
bucket are reachable only by an on-demand `verifyAuditChain`. (b)
**`PipelineJobRequest` is deliberately unchanged.** The chain path CAN re-dispatch
(`dispatch_with_retry` loops on a transport error), but it writes NO audit chain
at all: the only non-test `ExecutionLedger::new` is in
`execute_job_with_full_features` and the only `set_audit_ledger` is on the
single-node path, so `execute_pipeline` mints neither — and every production
entry point passes `ChainDispatch::Disabled` besides. A `dispatch_attempt` there
would partition nothing that exists. (c) **The partition is only as good as the
stamp reaching the worker.** No test in this workspace can drive
controller-dispatch → NATS → worker → S3 end to end; the guard is the live read
of the ledger after deploy, the position #767 and #769 both took about their own
changes.

**No lint check was added and `--count` stays 86.** Two candidates were measured
first and both have a population of ONE, the bar this repo does not ship at. (i)
*"a conditional-append signing segment must have a non-default wire snapshot"* —
`signing_payload` holds FOUR conditional segments (`:egress=`, the sealing block,
`:idem=`, `:attempt=`) and exactly ONE has a non-default snapshot (the one added
here), so the check would ship at 3 and the repo does not re-add baselines
(check 52's own rule). (ii) *"`ExecutionLedger::new_for_attempt` must be the
producer's constructor"* — `ExecutionLedger::new*` occurs ONCE in non-test worker
code, which is the same population #769 measured and rejected for the same
reason. The structural answers are stronger than a grep in both cases: the
snapshot pair is in the same file with a docstring saying why there are two, and
the ledger has one construction site the compiler funnels every caller through.

**Instruments, and deliberately no alert.** Both counters are PRE-SEEDED
(`talos_audit_ledger_duplicate_deliveries_total{scope="batch"}` — the only scope
with a live increment site, because the writer cannot see a cross-batch copy —
and `talos_audit_chain_duplicate_deliveries_total`). NOTHING alerts on either:
at-least-once delivery is the transport working as designed, and an alert here
would be the same train-the-operator-to-ignore-it defect the classification
removes. `TalosAuditVerificationFailures` was REVIEWED and left unchanged
because the change made it strictly MORE selective — a duplicate delivery now
touches no series it selects — with two promtool cases pinning both directions
(duplicates climbing fires nothing; a real break still pages while they climb).
The sweep reports `jobs_with_duplicate_delivery` beside the verdict and never
inside `failed`; `security_audit`'s `audit_chain_verification` renders a
duplicate-only chain as PASS with the count DISCLOSED, because "2 events,
verified" and "1 event delivered twice" otherwise render identically. The
GraphQL surface exposes `duplicate_delivery` as a `kind` and a per-job
`duplicateDeliveries` count.

**No lint check was added and the count stays 86.** TWO candidates were
measured first, and both have a population of ONE, which is the bar this repo
does not ship at. (i) *"a `ChainBreak` consumer must branch on
`is_tamper_evidence`, not `breaks.is_empty()`"* — measured workspace-wide,
`breaks.is_empty()`/`breaks.len()` appears at **3 lines and none is a verdict**
(two test assertions and `security_audit`'s Broken-arm count, itself fixed here
to count tamper evidence only); `ok` is computed in exactly ONE place. (ii)
*"the worker runtime may mint an `ExecutionLedger` only above the retry loop"* —
`ExecutionLedger::new` occurs **once** in non-test worker code and
`append_terminal_anchor` **once**. The structural answers are already stronger
than a grep: `ok` has one home, `seal_job_audit_chain` is the one place an
anchor is appended and the labelled block gives it one call site, and the
`From<&ChainBreak>` GraphQL mapping is an EXHAUSTIVE match that FAILED TO
COMPILE until the new variant was classified — which is the guard that a grep
would only imitate.

**The one measured SURVIVOR, stated rather than implied.** Reinstating a
per-attempt `ExecutionLedger` inside
`execute_job_with_context_and_timeout_internal` — i.e. the original defect —
leaves all 639 `talos-worker-runtime` tests green. Nothing in the suite can
observe it: the anchor's only externally visible effect is a NATS publish, and
the retry loop needs a wasmtime engine, a compiled component and a NATS server
to drive. What IS covered is the sealing RULE (`seal_job_audit_chain`'s four
tests, three of which fail under their own mutations) and the classification the
defect used to trip (`verify_chain`'s). The honest guard for the call site is
the live read of the ledger after deploy — the same position #767 took about its
sweep — not a test that does not exist.

## Three artefacts that described a system that does not exist (2026-09-07)

**PRESENCE IS NOT FUNCTION at the config and documentation layer** — the class
"The verifier that could never read the ledger it verified" records one level
up. A credential, a documented variable and a checked-in snapshot each LOOKED
like the thing they named and were not it. None is a vulnerability; each is a
statement an operator acts on that has been false for weeks or months, and in
every case the artefact and the code drifted apart with nothing able to say so.

### (W1) A credential for a principal that does not exist

`docker-compose.yml` handed the WORKER `AWS_ENDPOINT_URL`,
`AWS_ACCESS_KEY_ID = ${MINIO_WORKER_USER}`, `AWS_SECRET_ACCESS_KEY`,
`AWS_DEFAULT_REGION`, `AWS_S3_FORCE_PATH_STYLE` and `MINIO_BUCKET` under the
comment *"MinIO / S3 for audit ledger"*; the Helm worker Deployment mounted the
same pair out of the bootstrap Secret as **REQUIRED** `secretKeyRef`s;
`install.sh` generated and stored them; `values.yaml` declared them;
`.env.example`, `QUICKSTART.md`, `scripts/setup-dev.sh` and `ci.yml` all
carried them; and `deploy/helm/talos/README.md` called it a *"least-privilege
worker writer"*. Three independent things were wrong at once, measured
2026-09-07:

* **The worker has no reader for those names.** `grep -rn 'AWS_\|MINIO_'
  worker/src talos-worker-runtime/src` → nothing. The worker publishes audit
  events to the NATS subject `talos.audit.ledger`; the CONTROLLER is the only
  process that writes the object store.
* **The principal does not exist.** `mc admin user list` on the live MinIO
  (READ-ONLY) returns exactly two users — `talos-controller`
  (`audit_write_only`) and `verifier-…` (`audit_read_only`). `minio-init`'s
  script issues `mc admin user add` twice and names `$$MINIO_WORKER_USER`
  nowhere; #767's `minio-provisioning` Job likewise.
* **It was a REQUIRED key for an unread value.** Unlike the `OCI_REGISTRY_*`
  refs three lines above it, the worker's `secretKeyRef` carried no
  `optional: true`, so a bootstrap Secret without those keys wedges the Pod in
  `CreateContainerConfigError`.

Removed end to end. **On upgrade an existing bootstrap Secret keeps the two
stale keys and nothing selects on them** — the only chart-wide consumer of that
Secret's CONTENT is `talos.secretChecksum`, which hashes the live Secret, so
unchanged extra keys keep the hash stable and trigger no bounce. They can be
dropped at the next rotation.

**The brief's own premise was partly refuted and the refutation matters**: the
worker DOES have an S3 code path. `talos-worker-runtime/src/context.rs` reads
`S3_ENDPOINT` / `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` / `S3_REGION` for
the `talos:core/object-storage` WIT host functions, which only the
`automation-node` (`Trusted`) world may import. Different names, different
subsystem, deliberately unset everywhere — see (W2).

**Adjacent break found in the same files and fixed here.** `scripts/setup-dev.sh`
and `.github/workflows/ci.yml` both write a `.env` naming the DEAD worker pair
and **not** `MINIO_VERIFIER_USER`/`_PASSWORD`, which #767 made a `${VAR:?}`
requirement in `docker-compose.yml`. Compose interpolation is FILE-GLOBAL —
verified empirically, `docker compose build a` on a two-service file fails on a
`:?` in service `b` — so a fresh `make setup` produced a `.env` that could not
bring the stack up at all, and `ci.yml`'s image build would have failed the
same way. Latent only because both are `workflow_dispatch`/manual paths that
have not run since #767.

### (W2) Four documented variables that configure a different subsystem

`docs/deployment.md`'s env table and its "S3 / MinIO Configuration" section
both listed `S3_ENDPOINT` / `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` /
`S3_REGION` under the sentence *"Talos uses S3-compatible object storage for
the audit ledger and module artifact storage"*. **Both halves are false and the
failure is silent**: an operator on AWS who set exactly those four gets no
error and a dark ledger. Measured: the ledger reads
`AWS_ENDPOINT_URL`/`MINIO_ENDPOINT`, `MINIO_BUCKET`, `AWS_S3_FORCE_PATH_STYLE`,
the SDK's `AWS_*` chain for the writer and `AUDIT_VERIFIER_*` for the verifier;
and NOTHING in the workspace writes a module artifact to an object store
(compiled WASM lives in `modules.wasm_bytes` and the OCI registry, and the only
`put_object` callers are the audit ledger and `talos-offhost-backup`). The
two-identities table twelve lines below was correct the whole time — the
section contradicted itself.

`docs/configuration-reference.md` already had it right (*"worker | S3 endpoint
for module host storage"*), so it is now stated to be the AUTHORITATIVE list
and `docs/deployment.md` points at it. Both files gained the region asymmetry
that neither recorded: the VERIFIER resolves `AWS_REGION`/`AWS_DEFAULT_REGION`
itself with a `us-east-1` fallback, while the WRITER takes whatever
`aws_config::load_defaults` resolves — so a deployment setting neither can have
a writer that errors on region and a verifier that quietly assumes one.

**A lint was built, MEASURED and REJECTED; `--count` stays 86.** The candidate:
*every backticked `UPPER_SNAKE` token in `docs/deployment.md`'s env tables must
be read somewhere in `.rs`, compose, helm or a script.* Run against pristine
`origin/main` it reports **2 of 49 tokens**, and neither is an `S3_*` — because
the `S3_*` four DO have a reader, just not the one the doc claimed. **The
detector is green over the entire defect it was written for**, which is the
gate-that-doesn't-gate shape (#624, checks 64/65). It reports the same 2 on the
fixed tree, so it would also ship above zero. What it DID surface is a third
instance of the class, now corrected in the doc: `GRAPHQL_MAX_DEPTH` and
`GRAPHQL_MAX_COMPLEXITY` are documented as tunables with defaults `10`/`5000`
and are **hardcoded** `limit_depth(15)` / `limit_complexity(5000)` in
`controller/src/bootstrap/services.rs` — so the name is not a knob and the
documented depth default was not even the live value. No knob was invented
(that is a behaviour change); the rows now say what is true.

### (W3) A snapshot with a regeneration command and no gate

`frontend/schema.graphql` is graphql-codegen's offline input. Measured: last
regenerated 2026-07-27 (`aa173fa9`); the compiled schema is 2030 lines against
the snapshot's 1870, a **186-line diff — 173 added, 13 removed** (the removals
are doc-comment rewordings, not dropped fields, so the brief's "additive only"
was close but not exact). Nothing in `frontend/src` queried a drifted name, so
nothing was broken — it was a snapshot that stopped being true six weeks
earlier and had no way to say so. Check 64's lesson: a sweep is a snapshot, not
a gate.

`talos_api::schema_sdl()` is now the ONE construction and both the
`dump_schema` binary and
`schema_snapshot_tests::the_checked_in_snapshot_matches_the_compiled_schema`
call it — two expressions for "the schema" is how a writer and a checker drift
apart. **Why a TEST and not a lint, argued rather than assumed**: the
comparison needs the COMPILED schema, and `scripts/lint-structural.sh` has no
Rust build on its default path (check 7's clippy is gated behind
`TALOS_LINT_CLIPPY=1` precisely because a 60-90s build is too much), so a lint
leg could only compare text to text — it could say the file exists and never
that it is current. A `#[cfg(test)] mod` inside `src/` also runs in CI's
ordinary unit job with no runner registration, so it cannot rot the way check
64's hand-maintained `tests/`-binary lists do. Mutation-proved twice: one
flipped field nullability, and the REAL pre-fix snapshot restored from `HEAD` —
both red, restore green, and the failure message prints the exact regeneration
command.

**`schema.ts` needed its OWN gate, and the measurement is why.** It has zero
direct importers but reaches 49 files through `graphql.ts`'s
`export * from "./schema"`. Pinning `schema.graphql` proves the INPUT is
current and says nothing about whether the derived output was regenerated —
and on this tree both were stale TOGETHER, which is exactly why neither
noticed. Nothing else in the frontend gate can see it: eslint EXCLUDES
`src/generated/**`, and `tsc --noEmit` only fails when some file references a
type the stale output is MISSING, so a snapshot that merely lacks new types
typechecks perfectly. `quality.yml`'s frontend job gains a
`npm run codegen && git diff --exit-code -- src/generated` step. Deliberately
NOT in `make lint-frontend`: that target skips itself when
`frontend/node_modules` is absent, and a gate that skips is not a gate.
Determinism was verified rather than assumed — codegen run from two different
starting states produced byte-identical output.

### (W4) An improvements list that contradicted its own components

Found LIVE 2026-09-07 12:03Z. The moment `pa-quality-judge` crossed RFC 0012
P2's 3-run ledger floor, `get_readiness_breakdown` scored it `54/100`,
`basis: "ledger"`, reliability `15/50` from `executions_30d: 3,
source: "sub_workflow_runs"` — and `improvements[0]` in the SAME response read
*"Execute the workflow at least once to establish reliability baseline"*,
`points_available: 50`, `measured: true`. Check 74's contradiction shape, and
both halves were computed correctly from DIFFERENT inputs: P2 moved the SCORE
onto the child-run ledger and left the ADVICE keyed on the
`workflow_executions` count, which is 0 for a sub-workflow by construction.

`build_readiness_improvements` is now a PURE function that **does not receive
that count at all** — its reliability and freshness inputs are the ones the
score was computed from and the basis says which table they came from, so a
caller cannot hand it a pair that disagrees with the score. Three more things
the same reading fixed:

* Two arms were gated on `!is_child`, so a LEDGER-measured child — back on the
  full 100-point scale — was the only kind of row scored out of 100 that was
  never told how to move 70 of those points. The gate is now
  `is_unmeasurable_child`, the same predicate #770 chose for the `below_50`
  exclusion and for the same reason.
* `points_available` is `max − score` per component. The freshness arm fired
  only at `freshness == 0.0` and offered a literal `10` where the gap is 20,
  and said nothing at `freshness == 10.0` (8-30 days old) where the gap is 10 —
  so `total_points_available` understated the real gap in both directions.
* Every reliability/freshness line now names its `source` table. Two numbers
  under one field name from two tables is how this stayed invisible.

**`CHILD_UNMEASURED_REASON` was one release behind the ledger too.** It asserts
reliability is *"read from that table and from nothing else"* — false the
moment `sub_workflow_runs` holds a row, and `get_all_readiness_scores` prints
`ledger_runs: 1` two fields above it in the same object. The per-workflow
surfaces now call `child_unmeasured_reason(ledger)`, which is three-valued: no
evidence → the constant verbatim; runs below `LEDGER_MIN_RUNS` → a sentence
that says the ledger IS a second source and the shortfall is the COUNT, not the
source; at or above the floor there is no unmeasured reason at all. The
constant is KEPT for the population-level `why` in `get_all_readiness_scores`,
where there is no one child's evidence to speak about.

Reproduced before it was fixed: the renderer was extracted PRESERVING the
pre-fix logic, the test seeded `ReadinessBasis::LedgerMeasured` at n=3 and
failed with the live sentence in the assertion output, and only then was the
logic replaced. Three mutations on the fixed tree are red (re-blinding ledger
children via `is_parent_dispatched`; the literal-10 freshness arm; the
below-floor reason reverted to the constant). `retry_warning_for` was lifted to
one home in the same pass — it is rendered BOTH as an `improvements` entry and
as `components.risk.detail.retry_warning`, and two copies of a predicate is two
answers to one question in one response.

### (W5) Check 55 stopped at the crates a background loop does not live in

The SLA-breach monitor in `controller/src/bootstrap/background.rs` decoded the
NULLABLE `workflow_sla_thresholds.notification_webhook` with
`Row::get::<String, _>(..)` inside a `tokio::spawn`ed loop. `Row::get` PANICS
on a decode failure; the NULL is not a corner case but the DOCUMENTED
API-polling configuration that migration
`20260404000001_nullable_sla_notification_webhook.sql` exists to allow. **A
panic in a spawned background task is worse than one in a request handler**:
nobody is waiting, nothing restarts it, nothing logs it beyond tokio's default
stderr line — the alerter is simply off for the process lifetime while every
surface still reports the thresholds as configured. Check 55's scope is
DB-LAYER CRATES, so it structurally could not see a controller-bin file: the
population was 5 and the check was green.

Scope widened to `controller/src/bootstrap/` + `controller/src/main.rs`, and
the qualification is measured on the same evidence the DB-layer crates were:
`r`/`row`.get("…") in those paths is a sqlx row read in **5 of 5** occurrences
and a serde_json `.get` in 0 — which is why mcp-handlers and the engine stay
OUT of scope. Run against the real pre-fix file it reports exactly those 5 and
0 on the fixed tree; two mutations (a reinstated bare read in `background.rs`,
a fresh one in `main.rs`) are reported by line.

**Note for whoever merges this**: `origin/main` advanced to #772 (RFC 0012 P3)
mid-session and independently burned the same 5 sites down with the same
warn-and-continue shape. This change carries the fix too so its own lint is
green; the merge resolution there is "take either side". #772 did NOT widen the
check, and did not touch the improvements renderer either — (W4) is still live
on `origin/main`.

**Recorded remainder, NOT fixed here: a spawned loop's death is invisible.**
Measured 2026-09-07 — `controller/src/bootstrap/` + `main.rs` hold **63**
`tokio::spawn` sites and **62** discard the `JoinHandle` outright. The
sixty-third (`spawn_catalog_missing_wasm_gauge`) collects handles only to
sequence a metrics gauge and awaits them as `let _ = h.await;`, discarding the
`JoinError` as well. There is **no `std::panic::set_hook`** anywhere in
`controller/` or `worker/`. So a panicking background loop produces one
unstructured stderr line, no metric, no audit event and no restart, and every
operator-facing surface keeps reporting the subsystem as configured. Building a
supervisor is a separate change; what this one buys is that the most likely
CAUSE of such a panic — a bare `.get` on a nullable column — can no longer be
added to that directory silently.

## A statement that has never once executed, rendered as "nothing here" (2026-09-07)

Three surfaces asserted a determinate negative — the misleading-report class
(checks 74, 76, 79/79b, 81) — with a cause none of those checks can see: **the
SQL never ran.** `sqlx::query("…")` takes a runtime `&str`, so a statement
naming a renamed column is invisible to rustc, to clippy and to CI's sqlx
offline cache (which covers only the `query!` MACRO forms). The population is
now measured and gated by **check 88**.

**(Y1) `webhooks: []` from a statement that cannot PREPARE.**
`AnalyticsRepository::list_workflow_webhooks` asked `webhook_triggers` for
`endpoint_path` and `is_enabled`. That table's flag column is `enabled`, and
there has never been an `endpoint_path` column **at all** — the endpoint is
DERIVED from the id (`/webhooks/{id}`), which is why the statement could not be
repaired by a rename and why `webhook_endpoint_path` now has ONE home. Its
caller `get_workflow_dependencies` did `.unwrap_or_default()`, so `webhooks: []`
and `webhook_count: 0` were a determinate negative on every call. **The brief
named one statement; there were two** — `list_webhooks_for_modules` is
byte-identical in its column list and feeds `list_workflow_triggers`, which DOES
route the read through a `Readings` ledger, so that tool has been honestly
reporting `webhooks: not_measured` forever. Both now bind `user_id` as well:
the callers do gate ownership upstream, but `workflow_id` is not the tenant half
and check 70's lesson is that a statement should not rely on caller discipline.
All three reads in `handle_get_workflow_dependencies_list` now go through a
`Readings` ledger, and each COUNT is marked derived exactly when ITS OWN source
read failed — not whenever anything failed, because `module_count` comes from
the graph and is still measured when the NAME lookup is not.

**(Y2) A filter on a status the schema does not have.** `workflows_needing_schema`
filtered `w.status = 'published'`. The lifecycle enum is `draft | active |
archived` (migration `20260318000000`) and `handle_list_workflows` **refuses
`published` as a filter value in so many words** — *"the schema has no rows with
that value so accepting it would silently return an empty list"* — so the
hygiene check reported `[]` and `count: 0` for every operator on every run.
**The brief said nothing has ever written that value; that is refuted.** Exactly
one writer does — `insert_published_internal_workflow`, used by
`plan_and_execute_workflow` — and it writes `workflow_type = 'internal'` in the
SAME INSERT, which the predicate's very next clause EXCLUDES. So the filter was
not merely unmatched, it was **self-contradictory**: the only rows the status
clause admits are rows the type clause rejects. (Live fleet: 0 at
`status='published'`, 0 at `workflow_type='internal'`; 17 active / 11 draft / 8
archived.) The same literal was in a SECOND reader the brief did not name —
`ActorRepository::list_published_workflows_for_actor`, the **A2A agent card**,
so every actor's card advertised ZERO workflows and an empty card was
indistinguishable from an actor that owns none. Both now read
`talos_workflow_liveness::live_sql`.

**And the writer itself could never have written a row.** Driving
`insert_published_internal_workflow` in a DB test fails `23502`: it omits
`workflows.module_uri`, which is `NOT NULL` with no default, while every other
graph-workflow INSERT in that file binds `''`. So `plan_and_execute_workflow`
failed at its first write. **A PREPARE probe cannot see this** — the statement
parses and plans perfectly and only a real INSERT trips the constraint — which
is the sharpest statement of check 88's limits, and it was found by a test
rather than by the probe.

**(Y3) Three trigger paths, three different answers.** `trigger_workflow`
refused `is_enabled = false` and nothing else; `bulk_trigger_workflow` and
`enqueue_workflow` applied **no liveness predicate at all**. So an ARCHIVED
workflow was dispatchable from all three and a DISABLED one from two — check
78's "three of four entry points refused", one tool over. Archiving does **not**
clear `is_enabled` (none of the five `SET status = 'archived'` statements touch
that column), so on the reference fleet **all 8 archived workflows are
`is_enabled = true`** and nothing protected them incidentally. The decision is
`talos_workflow_liveness::is_dispatchable` — **deliberately NOT
`not_live_reason`**, which the brief named: a DRAFT must stay dispatchable
(`trigger_workflow` has always run one, a parent dispatches a child's draft
`graph_json` with no status predicate, and 11 of 36 workflows here are drafts,
4 with enabled schedules), so gating on LIVENESS would refuse those and create a
NEW disagreement in place of the one this closes. `not_live_reason` answers a
REPORTING question; a trigger gate is a DISPATCH question.
`OrchestrationError::WorkflowNotLive` is a new variant rather than a reuse, and
the exhaustive matches made the compiler name all four mapping sites — including
`talos-evaluation`'s, whose `_` arm would have rendered a deliberate policy
refusal as *"execution dispatch failed"* and sent an operator to look at NATS
(check 81(c)'s shape). `WorkflowDisabled` is KEPT for `replay`, which asks the
narrower question off a boolean it reads directly.

**Two behaviour changes, both new refusals, both stated plainly**: an archived
workflow can no longer be triggered from any of the three paths (it could from
all three), and a disabled one can no longer be bulk-triggered or enqueued. Both
gates sit ABOVE the graph load and the per-input loop, so a refusal costs no
dispatch and no partial batch an operator has to cancel.

**What was measured and NOT done.** The `is_enabled` gate is functional but
LATENT on this fleet — nothing is currently disabled — so the only refusal this
change can produce today is the archived one. The scheduler / webhook /
capability-resolution dispatch paths are deliberately untouched. And no live
trigger was fired against an archived workflow to demonstrate the pre-fix
behaviour, because doing so would EXECUTE it on the operator's only
environment; the evidence is the code (no path reads `status`, and
`WorkflowRecord` has carried it the whole time), the schema, and the fleet
counts above.

**One finding recorded and NOT fixed**: `controller/tests/common`'s
`create_test_organization` omits the `NOT NULL` `slug`, so it fails on every
call. It is the same class inside the harness; its other callers are outside
this change and `dead_statement_tests` seeds its own row instead.

## Failures nobody can see: a dead binding, and a loop that stops (2026-09-07)

Three surfaces where the platform could not SAY that something had stopped
working. Not a misleading report this time — a missing one.

### A push channel bound to a module the load cannot find

**Measured live.** Four Pub/Sub deliveries arrived (19:41Z x3, 19:57Z x1) and
every one failed with the byte-identical line
`WARN talos_google_cloud::handlers: gcp pubsub: dispatch failed
user_id=… error=load module for gcp dispatch`. Three things were wrong at once.

**(a) The log said nothing.** `error = %e` renders `Display` on an `anyhow`
chain, which prints only the OUTERMOST context — so
*"Module not found or access denied"*, the `module_id` and the `channel_uuid`
were all invisible. `{:#}` now renders the chain, the WARN carries
`channel_uuid`, and the module-load context names the channel and the module.

**(b) The module the channel names does not exist, and reading that took the
service.** The row is `integration_state (google_cloud,
watch/43773540-…)`, `value_format = 4`, so `module_id` is not readable from
psql; a temporary example binary drove the real `SecretsManager` +
`IntegrationStateService` (since deleted) and returned
`module_id = 51ff1d27-9e16-49cc-a7cf-92d7d61b495d`,
`display_name = "sandbox-monitoring"`, created 2026-07-17. That id matches **0
rows** in `modules`, has **0** `module_executions`, and appears in
`admin_event_log` **0** times — there is no record of how it went away. The
INTEGRATION row is healthy. Population: the fleet has 2 push channels
(`gmail`, `google_cloud`) and `google_calendar_watch_channels` is empty; the
gmail row binds no module, so **1 of 1 module-binding channels is dangling.**

**(c) Nothing durable was recorded, and the surface built for it was dark
because its input had never been produced.** `watch_channel_service`'s
`recent_failure` selects `event_type IN ('gcp_channel_push_rejected',
'gcp_dispatch_failed')` — and `google_calendar_audit_log` held **zero** rows of
either, ever, while carrying 18 rows for three other integrations. The cause:
`dispatch_monitoring_incident` has SIX failure exits and only TWO wrote the
audit row (signing, NATS publish). The four that fire in practice — module
load, the module-bound ceiling refusal, execution-row create, job serialise —
recorded nothing anywhere. **The fix is a wrapper, not a fifth call site**:
`dispatch_monitoring_incident` is now a thin outer over
`dispatch_monitoring_incident_inner` that writes exactly one row on any `Err`
(chain-rendered), and the two inline calls are DELETED so a failure cannot
write twice. A helper called at each exit is one forgotten call site away from
this state; a wrapper over the whole body cannot be forgotten.

**`module_name: null` was three states rendered as one**, and the read that
produced it was `.unwrap_or_default()` (check 74's shape). `module_binding` is
now four-valued — `none` (no binding) / `bound` / `missing` (set, and names
nothing this user can load — **every push fails**) / `unreadable` (the lookup
itself failed; calling that `missing` is a determinate negative over a query
that did not answer). `classify_module_binding` takes the lookup's own
`Result`, not a pre-flattened `Option`, and that is structural: with an
`Option` the classifier is correct and the CALL SITE can still hand it
`Some(HashMap::new())` on an `Err` — a one-line revert that **every test here
SURVIVES** (measured). Reading the `Result` makes the collapse a deliberate
rewrite; it does not make it impossible, and checks 74b/79b state that limit as
their own.

**What was measured and NOT changed.** `create_watch` gates the INTEGRATION
(ownership-checked) and accepts ANY `module_id` uuid, so a typo mints a
permanently-dead channel with no error and no trace — the most likely origin of
this fleet's state. Not fixed, because a correct create-time gate needs a
THREE-valued module-visibility read that does not exist: `get_module` folds
"not found" and "DB error" into one `Err` (check 79's leg (b)), and
`module_owned_by_user` has no `user_id IS NULL` arm so it DISAGREES with the
dispatch predicate about a shared catalog module — a gate on either would be a
third answer to a question that already has two. **No MCP tool lists GCP watch
channels** (grepped; `get_public_url_status` only prints prose telling the
operator to "list endpoints via the watch-channels API"), and
`get_platform_hygiene_report` / `list_workflow_triggers` do not know push
channels exist. Wiring one in would give `talos-hygiene-service` a dependency
on `talos-google-cloud`, inverting its layering. Recorded.

### A background loop can panic, or simply stop, and nothing says so

Package 20 (W5) recorded this remainder and left it. **Re-measured with a
statement-aware inventory** (`scripts/background-task-inventory.py`, added
here): `controller/src/bootstrap/` + `main.rs` hold **54** `tokio::spawn` call
sites — not 63; the difference is comment lines plus five uses of
`tokio::spawn` as a FUNCTION VALUE handed to
`async_graphql::dataloader::DataLoader::new`, which are not spawn sites — of
which **45 are loop-shaped** and exactly **one** binds the `JoinHandle` (and
discards the `JoinError`). `set_hook` occurrences in `controller/`, `worker/`
and `talos-worker-runtime/`: **0**.

**Two instruments, and they answer different questions.** Both live in the new
leaf crate `talos-task-supervision`.

* `install_panic_hook(process)` — installed in BOTH binaries immediately after
  the tracing subscriber, before anything can spawn. One structured line on
  target `talos_audit`, `event_kind = "task_panicked"`, carrying `process` /
  `thread` / `location` / a control-char-scrubbed 300-char message, plus
  `talos_task_panics_total{process}`. It covers EVERY panic in the process,
  including code nothing wraps. **It cannot name the task**: a tokio worker
  thread is `tokio-runtime-worker` and the location is wherever the panic was
  raised, usually a callee. The hook must never panic itself (a double panic
  ABORTS), so the payload downcast falls back to a fixed string, the message is
  truncated on a char boundary, and the counter is constructed before the hook
  is installed.
* `spawn_supervised(BackgroundTask, fut)` — applied at **42 of the 54** sites,
  and it sees the shape a panic hook structurally CANNOT: **a clean exit.** A
  loop that `break`s, or whose `while let Some(_) = rx.recv().await` ends
  because the channel closed, returns `Ok(())` — no panic, no stderr line, no
  trace at all, and the subsystem is off for the process lifetime while every
  status surface still reports it as configured.
  `talos_background_task_exits_total{task, outcome}`.

The **12 sites not wrapped**, named rather than counted: three one-shot startup
sweeps in `background.rs` that only LOOK like loops to a windowed scan
(`grandfather_embedding_model`, the crash-recovery sweep, the actor-memory
embedding backfill), three detached per-event tasks there, three in `main.rs`,
two in `services.rs`, and the one handle-bound compile task. Each is a one-shot
whose death is bounded to one event, and the panic hook still covers it.

**Nothing is restarted, deliberately.** Restarting a loop whose panic is
deterministic would spin, and deciding per-task whether a restart is safe is a
separate change. What this buys is that the death is SAYABLE.

**Cardinality.** `BackgroundTask` is an ENUM whose variants, labels and `ALL`
array come from ONE macro table, so the label set is closed BY THE COMPILER and
a variant that the pre-seed loop misses is not expressible — no hand-maintained
parallel list, and therefore no lint. `EXIT_OUTCOMES` is three-valued
(`panicked` / `completed` / `cancelled`): a `JoinError` is either a panic or a
cancellation, and folding an abort into "panicked" would report a deliberate
shutdown as a defect. All 127 series are PRE-SEEDED at 0. **The `process` label
is seeded with ONE value per process** — a `{process="worker"}` series on a
controller would be a seeded combination nothing there can increment, which is
the same defect as a dead metric. The worker registers into
`prometheus::default_registry()` (what `get_prometheus_metrics` gathers and
`seed_circuit_breaker_series` already seeds into), so its series survives an
OTEL exporter-build failure.

**Two alerts, both `warning`, and the argument is not the refusal one.** A
refusal counter fires when the policy is WORKING; a panic in a spawned task is
never working as designed, so it has no legitimate steady state above 0 —
`TalosTaskPanic`. `TalosBackgroundTaskExited` is the same argument for the
shape the hook cannot see, and it is the one that names WHICH loop.
`warning` rather than `critical` because the blast radius is one task.
Three `promtool` cases in `observability/alerts_test.yml` (pinned
`prom/prometheus:v2.48.0`), the first of which drives permanently-zero
pre-seeded series and asserts SILENCE — the shape a healthy controller has for
its whole lifetime, and the one an ABSENT series renders identically.

**The wiring is guarded, because it is the half nothing else can see.** The
crate's own tests prove the wrapper counts and logs; they cannot prove the 42
loops go through it, and reverting one site is behaviourally identical on a
healthy process. `task_supervision_wiring_tests` pins the supervised count, the
deliberately-bare count, and the two one-per-binary call sites
(`install_panic_hook`, `register_metrics`) — all three mutations red. Check 58
cannot see any of this: it asks whether a `TalosMetrics` FIELD has an increment
site, and these collectors are not `TalosMetrics` fields at all.

### The scheduler refusal counter: six survivors, not one

Package 24 recorded ONE surviving mutation on `talos_dispatch_refused_total`.
**No such series exists** — the instrument is
`talos_scheduler_dispatches_total{phase,outcome}`, written through one
`record_dispatch` helper — and deleting each of its **17** call sites in turn
found **SIX** survivors, while the `denied` site the note points at was already
caught. The two existing guards cover different things and neither covers the
six: `record_dispatch_moves_every_seeded_series` drives the WRAPPER, which is
exactly the property that stays true when every call site is deleted (check
58's stated wrapper limit); `every_terminal_path_records_an_outcome` is
anchored on a bare `return;`, and two of the six are the neighbour-vouching
limit that test DOCUMENTS actually happening, while the other four — the
wall-clock-timeout arm and the three tail arms (`completed`, `fenced`, the
terminal `failed`) — reach their end with no `return;` at all.

`every_recording_site_is_still_there` pins the per-outcome call-site count
(`completed 1, failed 10, skipped 3, denied 2, fenced 1`) plus a tripwire that
every call in the region is enumerated. **Re-running all 17 mutations against
it: 17 caught, 0 survivors.** One thing measured rather than reasoned: the
tripwire's first version counted `record_dispatch(` and read 18 on a HEALTHY
tree, because the function's own DEFINITION sits inside the scanned region.

**"The other pre-seeded paths" — the number is 29, and they are RECORDED.**
`talos-metrics` pre-seeds 29 collectors; mutation-testing all of them is ~80
build+test cycles and was not attempted. What WAS measured, in the same crate
and therefore cheap: all three `scheduler_readiness_*` publish sites SURVIVE
their own deletion — the pure `decide_hold` is well tested, the wiring that
publishes it is not. The cheap substitute ("does any file referencing the
collector contain an assertion") was built and REJECTED: it answers yes for 28
of 29, i.e. it only proves the file has tests somewhere. A grep cannot answer
"would deleting this call site turn a test red"; only mutation can.

**No lint check was added and `--count` stays 88.** Two candidates were
considered and both are answered structurally instead. "A long-lived
`tokio::spawn` must go through `spawn_supervised`" has a population of 54 in
ONE file and no way to tell a loop from a one-shot textually (the 60-line
window in the inventory script misclassifies three of 45 in both directions) —
the in-file count test is stronger and costs no check number. "Every
`BackgroundTask` must be pre-seeded" is not expressible as a defect: the enum
and the seed list come from one macro table.

## Sub-workflow dispatch (engine)

Every parent node that runs a sub-workflow (judge, ensemble, reflective-retry, llm-dispatch, sub_workflow) uses the shared dispatcher pattern in `controller/src/engine/parallel.rs`:

1. **`execute_subworkflow_graph(wf_id, trigger_input, nats, shared_key)`** — the canonical invocation path. Loads the graph, builds an engine, registers a synthetic `__trigger__` node, runs `run_with_seed`, collapses the output. Returns `Result<JsonValue, SubflowError>`.
2. **`collapse_subworkflow_output(ctx_results, sub_engine)`** — flattens per-node results. Single terminal → its unwrapped output (what parent nodes expect). Multiple terminals → label-keyed map (diamond fallback).
3. **`JudgeVerdict::from_collapsed(&collapsed)`** — types the `{score, passed, reasoning, feedback, not_applicable}` parse; `malformed_field_count` > 0 surfaces bad judge workflows loudly. **Judge verdicts are three-valued.** The optional `not_applicable: bool` (absent → false; present-but-not-bool → false + malformed++) marks a run with NOTHING TO JUDGE — a quiet inbox, an empty batch. Such a verdict is recorded into `judge_scores` as an ABSTENTION ROW (`not_applicable = true`) and excluded from every aggregate structurally (`FILTER (WHERE NOT not_applicable)`), with the count surfaced as `na_runs` beside the scored `runs` — scoring an empty run 1.0 inflates the average and saturates the signal, scoring it 0.2 drags the trend, and simply DROPPING the row destroys the abstention rate ("ran 17×, abstained 12×" became indistinguishable from "ran 5×"). The flag affects RECORDING only, NEVER routing: `passed` drives the gate exactly as authored on all three `on_failure` branches, so an abstaining judge must also set `passed` (usually `true`). Any new reader of `judge_scores` must carry the FILTER, and any renderer of `runs`/`avg_score`/`pass_rate`/`worst_score` must state that its population is scored-only. **Every judge-owned `__judge_*` key is written UNCONDITIONALLY by the single `build_judge_envelope`** (insert-or-REMOVE, never insert-or-inherit): the pass/passthrough branches build on top of the PARENT node's output map, so a conditionally-inserted key is inherited from caller data — an upstream module (or an earlier judge in a chain) emitting `__judge_not_applicable__: true` would otherwise erase the downstream judge's real datapoint from the trend, and `__judge_rejected__: true` would misroute a passing verdict. Same rule as the reserved-key strip on inbound trigger payloads: engine-authored keys are never caller-authorable.
4. **`dispatch_judge / dispatch_subworkflow / dispatch_ensemble / dispatch_reflective_retry / dispatch_llm_dispatch`** — one `&self async fn` per system-node kind, called from BOTH the main `run()` loop and `run_with_seed()`. Never re-inline the dispatch logic — extend the dispatcher.

**A sub-workflow bound to its OWN actor runs AS that actor** (2026-07). `AdapterSet` copies the parent's `actor_id` + ceilings verbatim into a freshly-built sub-engine; `bind_subengine_actor_and_ceilings` then (a) adopts the sub-workflow's own bound actor identity so direct `agent_memory::get/set` RPCs resolve against the sub-workflow's actor — matching the `__actor_context__` injection path, which already used it — and (b) narrows each ceiling to `most_restrictive(parent, sub-actor)`. Identity is adopted verbatim (not a lattice); ceilings only ever tighten. A sub-workflow with NO bound actor keeps the parent identity (reusable judge/classifier utilities run in the caller's context). Before this fix, a child bound to actor B invoked from a parent bound to actor A silently read A's memory (empty for the child's own keys) — the cross-actor recall bridge looked wired but returned nothing. Resolved atomically via `get_workflow_actor_binding` (identity + ceilings in one owner-validated JOIN) → `SubworkflowBinding` → `apply_subworkflow_binding`. Lint check 57 enforces the chokepoint. To bridge cross-actor memory, bind the reading workflow to the target actor (do NOT rely on a sub_workflow node re-scoping for you — it now does the RIGHT thing, but the whole-workflow bind is the simplest correct shape).

Use `test_subworkflow_contract` MCP tool while authoring a judge/reflection/classifier sub-workflow — it runs the same `execute_subworkflow_graph` + `collapse_subworkflow_output` path the parent will use, plus per-contract interpretation (judge verdict parse, class extraction). Catches shape bugs before wiring up.

## LLM key resolution (vault-first everywhere)

Canonical LLM provider vault paths live in **one place**: `job_protocol::LLM_PROVIDER_VAULT_PATHS` + `is_llm_provider_vault_path(path)`. Three consumers import from there:
- `controller/src/engine/parallel.rs::prefetch_llm_vault_keys` — injects keys into every worker job's secrets map so `llm::*` host functions can resolve them.
- `controller/src/secrets/mod.rs::get_llm_vault_keys` — per-user 60s-TTL cache; eagerly invalidated by `create_secret`/`update_secret`/`delete_secret` when path matches. Background sweep task in `main.rs` evicts expired entries every 300s (`LLM_KEYS_SWEEP_INTERVAL_SECS`).
- `worker/src/host_impl.rs::check_secret_allowlist` — DENIES these paths from WASM guest code even when `allowed_secrets: ["*"]`. Reserved for host-internal `llm::*` consumption.

Controller-side `LlmClient` uses `with_vault(SecretsManager, env_fallback)` — per-request resolution hits the same cache, so `rotate_secret anthropic/api_key` propagates to controller scaffolding AND worker sandbox LLM calls within one TTL window. Use `LlmClient::new(env_only)` only in tests.

**Adding a new LLM provider** = one change to `job_protocol::LLM_PROVIDER_VAULT_PATHS`. Everything else picks it up automatically. Also update `worker::host_impl::llm_key_lookup_paths` for the `vault_path → env_name` fallback mapping. **And** add the provider's API hostname to `job_protocol::EXTERNAL_LLM_HOSTS` — without this, a tier-1 actor's HTTP-host gate won't deny the new provider's endpoint.

## Per-actor LLM tier ceiling (data-egress privacy gate)

Actors carry a `max_llm_tier` ceiling — `tier1` = local Ollama only (data
must not leave host), `tier2` = external providers allowed (default).
Schema: `actors.max_llm_tier text NOT NULL DEFAULT 'tier2'` (migration
`20260424100000_actors_max_llm_tier.sql`). Operator tool:
`set_actor_llm_tier_ceiling(actor_id, tier)` (writes to `admin_event_log`
on every change).

The tier travels with the job — HMAC-bound in BOTH `JobRequest` AND
`PipelineJobRequest` signing payloads (appended at end per the
wire-format stability rule). An on-wire attacker can't downgrade a
tier-1 ceiling to tier-2 without invalidating the signature.

**`egress_scope` — a SEPARATE axis from `max_llm_tier`** (2026-07). `max_llm_tier`
historically drove BOTH "no external LLM" AND a blanket "no public network egress
at all" (the worker SSRF `local_egress_only`), so a tier-1 actor couldn't reach a
legitimate public API like Gmail even though its LLM was already ollama-pinned
(this broke the inbox organizers when PA went tier-1). `actors.egress_scope`
(`local`|`public`, NULLABLE) decouples them: it overrides ONLY the blanket
public-egress SSRF gate (`worker::context` `resolve_local_egress_only`), leaving
the LLM-provider deny + raw-`wasi:sockets` grant + public-IP-literal deny all
keyed to `max_llm_tier`. `NULL` = tier-derived default (`tier1`→local,
`tier2`→public — byte-identical to pre-split). `Some(Public)` on a `tier1` actor
= reaches declared `allowed_hosts` (Gmail) while STILL refusing external LLM. The
override travels HMAC-bound alongside `max_llm_tier` (conditional-append, so
default-`None` is byte-identical; a `public`↔`local` flip or strip fails
verification), stamped by `apply_actor_to_engine` (fail-closed to `Local`) +
every module-bound dispatch path, and narrowed across sub-workflows via
`EgressScope::narrow` (explicit `Local` on either side wins). Operator tool:
`set_actor_egress_scope(actor_id, scope)` (`admin_event_log`; scope null clears
the override). Core type `talos_workflow_engine_core::EgressScope` (fail-closed
`from_db_str`→`Local`). **The house pattern for a Gmail-reading privacy actor is
`max_llm_tier=tier1` + `egress_scope=public`**, NOT tier-2.

**Five enforcement surfaces in the worker** (all guarded by `self.max_llm_tier == Tier1`):
1. `host_impl::get_llm_api_key` / `get_llm_api_key_by_name` — refuse to resolve external-provider vault keys (the `decide_llm_tier_access` helper centralises this — see `llm_tier_decision_tests`).
2. `host_impl::resolve_vault_header` — refuse `vault://anthropic|openai|gemini/*` substitution into HTTP headers.
3. `wit_http::fetch` + `wit_http::fetch_all` — refuse hosts in `job_protocol::EXTERNAL_LLM_HOSTS` regardless of `allowed_hosts`.
4. `wit_graphql::execute` — same host deny-list.
5. `wit_webhook::send` + `wit_http_stream` — same host deny-list.

**Defense in depth on the controller side:** `build_encrypted_secrets_for` takes `max_llm_tier` and SKIPS the `resolve_llm_keys` prefetch entirely when `Tier1`. Tier-1 jobs never have an Anthropic/OpenAI/Gemini key on the wire (encrypted or otherwise) — bounds blast radius if a future bypass slips.

**Stamping the tier on a workflow execution:** ALWAYS use `talos_engine::actor_binding::apply_actor_to_engine(&actor_repo, &mut engine, actor_id)` (moved from `ActorRepository` in 2026-07 — lint check 51 forbids the repo→engine dep edge) — it sets `actor_id` AND `max_llm_tier` together and fail-closes to Tier-1 on DB error. Never call bare `engine.set_actor_id(aid)` — lint check 29 catches it (the setter is confined to `talos-workflow-engine/` and `talos-engine/src/actor_binding.rs`).

**Module-bound dispatch** (Gmail/GCal/webhook push notifications) is intentionally Tier-2 default — those paths fire individual modules without an owning actor. Operators who need tier-1 enforcement for inbound-event processing wrap the module in a workflow with an actor that has `max_llm_tier=tier1`.

## Secret Handling Rules (CRITICAL — security invariant)

**Plaintext secret values MUST NEVER leave the controller host** except through two audited paths:
1. **Outbound HTTP headers** — `vault://` resolution places the secret into a header for an external API call; the `Zeroizing<String>` is cleared after use.
2. **Tier-2 `expose_secret`** — explicit opt-in per module (`allow_tier2_exposure: true`), rate-limited (10/execution, 100/user/day), audit-logged at WARN level. Currently hardcoded to `false` across all engine dispatch paths.

**Every engine dispatch path MUST call `build_encrypted_secrets()`** (or the equivalent inline block) to populate the job's `encrypted_secrets` field. Sending `Default::default()` means the module silently loses access to all secrets — vault:// headers fail with `Notfound`, LLM calls fail with missing keys. This was a real bug in loop-node dispatches fixed 2026-04-16. When adding a new dispatch path (new system-node kind, new parallel executor, etc.), grep for `encrypted_secrets:` in `parallel.rs` and verify the new site matches the existing pattern.

**Secret flow through the system:**
- Controller: `SecretsManager::get_module_secrets(node_id)` + `get_secrets_by_paths(vault_paths)` + `prefetch_llm_vault_keys(user_id)` → plaintext `HashMap<String, String>` → `EncryptedSecrets::encrypt(map, key)` → AES-256-GCM ciphertext in `JobRequest.encrypted_secrets` → NATS publish.
- Worker: `EncryptedSecrets::decrypt(key)` → plaintext `HashMap` loaded into `SecretProvider` DashMap → WASM guest receives opaque `u64` handle only (Tier-1), never the string.
- No MCP handler, GraphQL query, or REST endpoint returns plaintext secret values. `get_secret` is internal-only. MCP is **read-only for secrets** (MCP-1201): `set_secret` / `delete_secret` / `set_secret_namespace` / `set_secret_expiry` / `rotate_secret` were removed because MCP API keys are long-lived bearer tokens with no 2FA equivalent — secret writes would have bypassed the `require_2fa + SecretsWrite` discipline the GraphQL surface enforces. Mutations go through `talos-api/src/schema/secrets/mutations.rs`; MCP retains the read surface (list, namespaces, usage, health, normalize). `refresh_oauth_token` is the lone MCP write that touches vault — provider-side token rotation, no MCP-supplied value crosses the boundary. The GraphQL `Secret` type has no `value` field.
- DLP `redact_json()` is applied to module execution output before DB storage (catches `sk-*`, `ghp_*`, Bearer tokens, etc.).
- Audit logs record `key_hash` (SHA-256 of path), never the value.
- Error messages reference `key_path`/`name` only, never decrypted content.

**Per-context AEAD subkeys + per-ORG root DEKs (formats v3/v4).** Every AES-GCM
path derives a PER-CONTEXT key — `HKDF-SHA256(ikm = a DEK, salt = label, info =
aad_context)` — rather than encrypting many rows under one shared key (keeps the
per-key message count ~1, so the random-96-bit-nonce birthday bound is
unreachable). **There are two DEK scopes** (`encryption_keys.org_id`): one
**global** DEK (`org_id IS NULL`) and one **per-organization** root DEK per org
(`org_id` set; exactly one active per org, lazily provisioned on first use). Both
partial-unique-indexed. So:
- **v3** = per-context subkey from the GLOBAL DEK.
- **v4** = the SAME derivation but from the writer-org's root DEK — so a
  compromised root key is bounded to one tenant, not the whole system.

DB-backed paths (`SecretsManager`: secrets / actor_memory / TOTP / webhook
secrets / exec output / module payloads) write **v4** when an org is resolvable,
falling back to **v3 (global)** for legitimately org-less rows (personal secrets,
standalone module executions). **Decrypt is IDENTICAL for v3 and v4** — the row's
`*_key_id` names the DEK (`get_dek` resolves global-or-org by id) and the subkey
re-derives from the same AAD; `decrypt_versioned` dispatches v0/v1/v2/v3/v4 on the
per-row `*_format` column. Only ENCRYPT differs (which DEK is the IKM).

**Adding a new AEAD writer?** Call `encrypt_value_aad_v4_or_global(value,
target_org, aad)` and resolve `target_org` from context — the workflow's org for
executions, the actor's org for memory, the secret's `org_id`. For
personal/user-keyed tables use `encrypt_value_aad_v4_for_user(value, user_id,
aad)` (resolves the user's personal org). **Bind the RETURNED format version,
never hardcode 3/4** (a v4 row mislabeled v3 fails to decrypt), and widen that
table's `*_format` CHECK to include 4. If a table has its OWN decrypt dispatch
(e.g. `decrypt_secret_record`) add the v4 arm there too, and guard any global
re-encrypt sweep to skip `format = 4` (don't downgrade org rows).

**Migrating EXISTING rows to per-org** (the cutover only converts NEW writes):
per-table sweeps `SecretsManager::re_encrypt_*_to_org` /
`ModuleExecutionService::re_encrypt_module_payloads_to_org` /
`talos_memory::re_encrypt_memories_to_org`, exposed as platform-admin mutations
`reEncrypt{Secrets,Memories,Outputs,ModulePayloads}ToOrg`. Poll the
`dekMigrationStatus` query until each `pending` is 0 → the global DEK is no longer
load-bearing for migratable data (org-less rows stay global by design). The
personal tables (totp/webhook/audit) have no sweep — they migrate lazily on next
write.

**Separate, NON-DEK derivations (NOT per-org, do not "fix"):** checkpoints fold
`execution_id` from the `WORKER_SHARED_KEY` (`checkpoint-aead/v2-per-execution`);
the worker secret-envelope folds the per-job AAD from the WSK
(`envelope-aead/v2-per-job`); OTLP headers fold `user_id`. These don't use the DEK
at all, so they're already isolated from a DEK compromise.

**Envelope deploy ordering:** workers must roll first/together with controllers —
a v1-only worker can't open a v2-sealed envelope (the v2→v1 decrypt fallback only
covers the reverse). New AEAD format versions need the format CHECK widened in a
migration (`20260617120000` introduced v3; the `2026062612*`–`2026062624*` set
introduced per-org v4 per table).

**Worker-side secret isolation:**
- `check_secret_allowlist(key_path)` enforces BOTH the per-module `allowed_secrets` grant AND the host-reserved deny-list (`is_reserved_host_secret_path`). The deny-list blocks LLM provider keys even with `allowed_secrets: ["*"]`.
- The allowlist matcher lives in ONE place: `job_protocol::vault_path_permitted`. Both controller (validation) and worker (runtime enforcement) import from there.

## Security Rules (MUST follow)
- NEVER log sensitive values (tokens, cookies, API keys, secrets). Log presence only.
- NEVER return internal error details to API clients. Log full errors server-side, return generic messages.
- NEVER fall back to plaintext credential storage in production. Require SecretsManager.
- NEVER store secrets unencrypted in the database. Use envelope encryption via SecretsManager.
- NEVER send `encrypted_secrets: Default::default()` in a dispatch path that should have secrets — use `build_encrypted_secrets()`.
- NEVER modify already-applied migration files. Create new migrations instead.
- ALWAYS use parameterized queries (sqlx `$1` bind params). Never string-concatenate SQL.
- ALWAYS use constant-time comparison for security-sensitive values (tokens, HMAC, CSRF).
- ALWAYS set HttpOnly, Secure, SameSite=Strict on authentication cookies.
- ALWAYS validate and sanitize external input at API boundaries.
- ALWAYS cap resource consumption (timeouts, memory limits, rate limits) for untrusted inputs.

## Performance Rules
- NEVER use N+1 query patterns. Batch with `WHERE id = ANY($1)` when processing collections.
- NEVER use unbounded in-memory collections. Set explicit size limits and eviction policies.
- ALWAYS add database indexes for frequently queried column combinations.
- Use `CREATE INDEX` (not `CONCURRENTLY`) in migration files (sqlx runs in transactions).

## Engine retry & wire-format rules (learned 2026-07-24, PRs #566–#570)

- **`modules.max_retries = 0` means "unset / no opinion", NOT "explicit no-retry".** Nothing writes that column, so its DB default (0) reaches every node. Do NOT stamp it verbatim onto nodes and do NOT "simplify" it to a blanket constant — resolve it through `talos_workflow_engine_core::default_max_retries_for_module(allowed_methods, capability_world)` (via `NodeTemplateRow::effective_max_retries()` at creation and the engine's absent-policy fallback). The default is **method-aware**: read-only / pure-compute worlds (minimal/secrets, or http/agent with a DECLARED GET/HEAD-only `allowed_methods`) get transient retries; governance/messaging/database/unknown worlds and state-changing HTTP fail closed to 0. **An EMPTY `allowed_methods` is UNKNOWN, not read-only** — the worker's three enforcement points (`host/http.rs` fetch + fetch_all, `host/graphql.rs`) read empty as "allow every verb", so an undeclared module can POST and must not earn a blind retry; `.all()` over an empty slice is vacuously true, which is how it used to read. Note the asymmetry: empty `allowed_hosts` and empty `allowed_secrets` both DENY all; `allowed_methods` is the only one of the three where empty means allow. A blanket-0 default made the entire retry machinery dead fleet-wide (the 2026-07-23 outage failed ~125 read-only fetches that each ran exactly once). Explicit per-node `retry_count` (including 0) always wins. Idempotent sends opt back into retries via `__idempotency_key__` → `effective_retries_with_idempotency` (HTTP-egress worlds only).
- **Pipeline steps retry too.** `execute_pipeline`'s per-step loop honors per-step `max_retries` gated by the transient classifier — do not re-hardcode step `max_retries: 0`. The transient classifier must match BOTH `"timeout"` AND `"timed out"` (the worker's own step-timeout message uses the latter).
- **The attempt-window arithmetic has ONE home: `talos_workflow_engine_core::attempt_window` (2026-09-06).** How much of a workflow's wall-clock budget one dispatch attempt may occupy is asked on two surfaces — the DISPATCHER (`talos_workflow_engine_nats::execute_job_with_retry`, where a wrong answer is a real cancellation) and the VALIDATOR (`talos_workflow_validation::retry_envelope_overrun`, where a wrong answer is advice an operator acts on). They had two implementations. The dispatcher's: `min(allowance, remaining − BUDGET_RESERVE_SECS(2))`, where `allowance = timeout_secs + TOKIO_WRAP_GRACE_SECS(5)`. The validator's: `envelope_secs <= budget_secs`. **They disagree by 7 s at the boundary**, so a node configured at 120 s inside a 120 s budget was reported as fitting and clamped to 117 s (`as_secs()` truncation) on attempt 1 of every run — measured live on the dev fleet: **9 such nodes across 3 ACTIVE workflows, 2 326 clamped attempts per 48 h** (`pa-ask-email` 1848, `pa-followup-approval-notifier` 382, `ops-critical-notifier` 96), every one on `attempt=1` of a run that then completed in under a second. `clamp_attempt_timeout`, `AttemptWindow` and the three constants MOVED to core (they are not copies — the dispatcher re-imports, `dispatch_allowance_secs` states the `+ 5` once), and the validator now SIMULATES the configured attempt sequence through the same `attempt_window_for_remaining`. Do not re-derive either half.
  - **Three outcomes, and the middle one was unsayable before.** `AttemptFit::Full` (silent) / `Clamped` (every attempt starts, at least one is cut short — a real finding, lower severity, category `attempt-window-clamped`) / `Truncated` (an attempt is never dispatched — the historical `retry-envelope` category). Fleet effect, measured: the old check reported **7** nodes; the new one reports **16** — 4 truncated (a strict SUBSET of the old 7) and 12 clamped, of which 3 were previously reported as the SEVERE finding (correctly downgraded: one 4 x 120 s node in a 450 s budget gets all four of its attempts, the fourth cut to 38 s) and 9 were reported as nothing at all. `ValidationSeverity` has only `Error`/`Warning`, so "lower severity" is expressed in the category and the wording; adding an `Info` variant would move every counter and response shape that reads a `ValidationResult` and was deliberately NOT done. `max_retries_within_budget` searches the same simulation, so it stays the exact inverse — and it MOVED by one retry on shapes the old formula's slack fitted an extra attempt into (`(120, 500, 240)`: 1 → 0).
  - **The prose in BOTH crates was one release behind the code.** `describe_retry_envelope_overrun` and `talos-mcp-handlers`' `describe_retry_bound` both said *"the retry loop has no view of the workflow deadline … the whole execution is dropped — discarding every sibling node that had already finished"*. False since #686 (2026-08-27, the same day that text was written): a clamped attempt that times out, and an attempt refused for want of budget, are both ORDINARY NODE FAILURES the engine routes (error edges, `continue_on_error`, DLQ) with sibling results kept. A single-string grep finds only ONE of the two — the handler's copy is reworded — so a fix to one crate really is a drift.
  - **The residual, stated rather than dropped.** The budget is still an OUTER `tokio::time::timeout` that drops the reactor future, and `BUDGET_RESERVE_SECS` makes the failure RECORDING likely, not certain: `handle_node_failure` awaits a `node_failed` INSERT, the DLQ write and a sibling reap, and a slower failure path still loses the race. The clamp covers module dispatch ONLY — `sub_workflow`/judge/ensemble nodes awaited inline are unclamped (the validator skips `system:*` nodes, so it claims nothing about them), and **`engine_dispatch_pipeline.rs` passes `deadline: None`**, so the chain path is unclamped too — dormant by config (`ChainDispatch::Disabled` at every production entry point) and RECORDED, not fixed.
  - **The clamp WARN is now attributed by cause.** `DispatchJob::budget_secs` (stamped beside `deadline` from the same `secs` on `ExecutionProgress`) feeds `clamp_cause`: `Configuration` (the allowance could never have fitted, even at t=0 — a graph problem `validate_workflow` now reports) logs at **debug**; `Consumption` and `Unknown` stay **warn**. `budget_secs` is ATTRIBUTION ONLY — it never enters the clamp, so `None` changes no timing, and `Unknown` is never demoted. **No metric was added**, and that is a measurement: `talos-workflow-engine-nats` has no `talos-metrics` dependency (it is reachable only transitively through `talos-workflow-engine`, which Rust does not permit), so a series would cost a new direct dependency edge — recorded and declined, which means the consumption clamp remains prose-only and cannot be alerted on.
  - **No lint was added, and here are the numbers so nobody re-measures.** "Clamp constants or `clamp_attempt_timeout` defined outside core" reports **1 file** on pristine main and 0 after — population ONE, which is the bar this repo does not ship at; the structural answer (one `pub` home, the constants deleted from the dispatcher) is already stronger. "An `envelope_secs <= budget` comparison outside core" reports 2 lines on main of which 1 is a legitimate test assertion (50% precision) and **3 on the FIXED tree, all of them the new comments explaining the fix** — check 73's self-report trap. `--count` stays **86**. Two mutations are open and measured SURVIVORS, both in the loud direction: re-inlining `job.timeout.as_secs() + 5` at the dispatch site is behaviourally identical and no test can see it (the guard is that the constant no longer exists in that crate), and passing `None` for `budget_secs` merely restores the WARN.

- **New signed wire fields use the conditional-append idiom.** When adding a field to `JobRequest` / `PipelineJobRequest` / `PipelineStep` that must be HMAC-bound, append it to `signing_payload` ONLY when non-default, guarded so an all-default message is **byte-identical** to the pre-field wire format (the deploy-compat invariant). Follow the existing `:egress=` / `:retries=` / `:idem=` / `:attempt=` segments (appended at the END, `#[serde(default, skip_serializing_if=…)]` on the struct field). Add the field to the wire-format snapshot + security test constructors in the same change — and add a NON-default snapshot too, with its own expected JSON and MAC hex: the all-default snapshot proves the field ships inert and says nothing about the bytes the field actually adds.

## Git Safety Rules (MUST follow)
- NEVER run `git checkout --`, `git restore`, or `git reset --hard` on files that show as modified in `git status` without first running `git stash`. Uncommitted changes are irrecoverable.
- ALWAYS run `git status` before any destructive git operation to understand what will be affected.
- ALWAYS use `git stash` (not `git checkout --`) when you need to temporarily revert files. Use `git stash pop` to restore.
- NEVER use worktree-isolated agents (`isolation: "worktree"`) when `git status` shows uncommitted modifications to files the agent will touch. Worktrees branch from HEAD, not the working tree — the agent will miss all uncommitted work.
- ALWAYS complete and verify data model changes (struct fields, migrations, protocol types) BEFORE launching parallel agents that construct those types. Otherwise agents use stale field names requiring manual reconciliation.

## Docker Build Notes
- BuildKit uses persistent exec cache mounts for `/usr/local/cargo/registry` and `/app/talos/target`
  (the `cargo build` RUN steps in `controller/Dockerfile` and `worker/Dockerfile`).
- Both mounts are `sharing=locked` (2026-07-06): the controller/migrate/worker images build in
  PARALLEL under compose bake, and the default `shared` mode let concurrent cargo processes race
  the registry unpack (`failed to open .cargo-ok … File exists (os error 17)`); a build killed
  mid-unpack leaves the cache corrupted so every retry fails.
- These mounts survive `docker compose build --no-cache` AND `make clean` (its prune keeps 8 GB).
  If builds produce stale artifacts or the `.cargo-ok` corruption above, purge them explicitly:
  `docker builder prune -f --filter type=exec.cachemount`, then rebuild.
- **cargo-audit + RustSec advisory database are baked into both the
  controller and builder images** at image-build time at the stable path
  `/opt/talos-advisory-db`. The compilation service passes
  `--db /opt/talos-advisory-db` to every `cargo audit` invocation so the
  path is explicit (see `compilation::container::ADVISORY_DB_PATH`) — env
  derivation via `$CARGO_HOME` would silently break because the runtime
  points it at a tmpfs path that gets wiped per pod. The DB is frozen at
  build — rebuild images monthly to absorb new advisories. Without the
  bake-in step, every `compile_custom_sandbox` / `install_module_from_catalog`
  / inline `rust_code` request fails closed in production with "cargo-audit
  exited with an error". This was the 2026-04-27 prod regression —
  cargo-audit was missing from `controller/Dockerfile` AND the advisory DB
  was missing from `Dockerfile.builder`.
- **Runtime compiles + lint pre-flights reuse a per-USER persistent
  `CARGO_TARGET_DIR`** (`/tmp/cargo-target/per-user/{user_id}`; knobs
  `TALOS_COMPILE_TARGET_CACHE` / `_DIR` / `_TTL_HOURS` — see
  `talos-compilation/src/target_cache.rs`). Second-and-later compiles only
  rebuild the user's `lib.rs` (measured 11× on the host path; prod's
  container path previously rebuilt the whole dep graph every call). The
  per-USER scoping is a SECURITY invariant, not an optimization detail: the
  build sandbox mounts the cache read-write and cargo fingerprints are not
  integrity checks, so a fleet-shared cache would let one tenant poison
  `.rlib`s that another tenant's build links. Never consolidate it. Idle
  user dirs sweep after 7 days (opportunistic, rate-limited).
  `TALOS_SDK_MACROS_PATH` overrides the baked `/app/talos_sdk_macros` for
  host-side runs (mirrors `TALOS_WIT_PATH`).

## WASM Module Development Rules (MUST follow)
- NEVER use top-level `serde_json::Value` to parse upstream payloads. Use typed `#[derive(serde::Deserialize)]` structs — 3-10x cheaper in WASM fuel. The `Value` type allocates a `HashMap<String, Value>` per JSON object; typed structs skip unneeded fields entirely.
- ALWAYS set explicit `max_fuel` on every workflow node. Default fuel (1M-5M) is rarely correct. Use `fuel_budget` in `hot_update_module` / `compile_custom_sandbox` to auto-calculate from expected payload shape.
- ALWAYS use `format=metadata` (Gmail) or field-limited queries (Jira `fields` param) when full response bodies aren't needed. Smaller payloads = less fuel + avoids the 65KB input limit.
- ALWAYS cap collection sizes: `MAX_RESULTS`, `take(N)`, thread caps. Match caps to schedule cadence (e.g., 15-min poll → `newer_than:15m`, not 30m).
- ALWAYS specify `capability_world` explicitly when compiling modules. Use least-privilege: `minimal-node` unless HTTP/secrets/etc. are needed.
- ALWAYS validate required config keys early in `run()` with clear error messages (e.g., `ok_or("Missing AUTH_HEADER config")`).
- ALWAYS use versioned API endpoints (e.g., `/rest/api/3/` not `/rest/api/2/`). Pin to the latest stable version to avoid deprecation (HTTP 410).
- ALWAYS run `validate_workflow` after modifying node configs. ALWAYS run `test_workflow` with assertions before considering a workflow production-ready.
- NEVER assume upstream input shape — check multiple possible formats (arrays, nested objects, trigger input) and return graceful empty results when no data is found.
- Delivering actor-memory content externally (email/webhook/chat)? Use the two-node delivery pattern (`docs/delivery-node-pattern.md`): compose (agent-node, memory, NO network) → send (http-node, network, NO memory). Do not request `automation-node` just to combine memory+HTTP — the split is the security design, not a workaround.
- **Reading actor memory to REPORT on it? Declare an input-freshness contract.** A memory reader cannot otherwise tell that its inputs are old: if the upstream writer failed (or hasn't run yet), the reader confidently presents yesterday's data as today's. Observed live 2026-07-25 on `pa-chief-of-staff` — it rendered 32-hour-old `meeting_prep/today` as "Heavy Meeting Day" *for today*, and the `inline_judge` passed it because that verdict only checked "is there a `priorities` array" (a SHAPE check, not a freshness check). Set per-node graph-json `requires_fresh: {"<memory_key>": <max_age_hours>}` (+ optional `on_stale: "annotate"|"fail"`, default `annotate`); the engine resolves each key's age against **the node's bound actor** and injects `__staleness__` = `{any_stale, entries:[{key, age_hours, max_age_hours, present, stale}]}` onto the node input. An ABSENT key counts as stale (no data ≠ fresh data). Pure helpers + semantics: `talos_workflow_engine_core::reserved_keys::{resolve_freshness_policy, build_staleness_report, describe_stale_entries}`. Two rules: (a) a composer that renders a user-facing report SHOULD surface `__staleness__` (e.g. "⚠ meeting data is from Friday") rather than silently omitting it; (b) declare the contract on the node whose ACTOR owns the keys — for a cross-actor sub-workflow, put `requires_fresh` on the node INSIDE the sub-workflow (where the bound actor is the key owner), not on the parent's `sub_workflow` node. Absent `requires_fresh` = no contract = byte-identical pre-feature behavior.
- **A composer built on a FAILED upstream branch must be able to say so — `__degraded_inputs__`.** Freshness (above) covers a stale MEMORY input; this covers a DEAD BRANCH, and they are the two ways a node's inputs can be wrong while its output looks perfectly well-formed. Observed live 2026-09-03 on `pa-chief-of-staff` (execution `0449ea71`): one of three gather branches died of fuel exhaustion, `collect` folded its error envelope into `items` as an UNLABELLED POSITIONAL element, the composing LLM did exactly what its prompt told it to ("if a source is empty or absent, simply draw fewer priorities from it — never fabricate"), and the deterministic `inline_judge` scored the result **1.0** — because, as in the freshness case one bullet up, that verdict only checked the SHAPE of each priority. The words "team", "unavailable" and "degraded" appeared nowhere in a briefing that had lost a third of its evidence. **Every guard in the 4-guard stack judges the OUTPUT, and a missing input DIMENSION is invisible from there.** The engine now derives, on every dispatch, the set of ANCESTOR nodes whose committed output `output_reports_error` (check 77's classifier — never `.as_bool()`), and injects `__degraded_inputs__` = `{any_degraded, count, truncated, entries:[{node, reason}]}` onto the node's input. Ancestors, not parents: in `judge → synthesize → collect → team_gather` only `collect` has the failure as a direct parent, and `collect` is the one node in the chain that renders nothing and judges nothing. Entries are **sorted by label** (petgraph's parent order is neither the author's nor stable — measured), deduplicated, capped at 16 with `count` still reporting the true total, and reasons truncated to 240 chars on a char boundary. Chokepoints: module dispatch, pipeline-chain head, the `collect` envelope itself (the node that claims `count: 3` while one of the three is an error envelope), and both judge kinds. **Nothing degraded ⇒ NO KEY ⇒ byte-identical to the pre-feature payload** — absence is the all-clear, and an "all clear" envelope would have changed every node payload in the fleet. Pure helpers: `talos_workflow_engine_core::reserved_keys::{build_degraded_inputs_report, describe_degraded_inputs, apply_degraded_inputs}`. Three rules: (a) as with `__staleness__`, a composer that renders a user-facing report SHOULD surface the gap ("⚠ team data unavailable — recall failed") rather than silently drawing fewer conclusions from it; (b) in a Rhai verdict/condition use the bound variables **`inputs_degraded` (bool) and `degraded_inputs` (array)**, NOT the reserved key — the key is set-or-REMOVE, so on a healthy run it is ABSENT, and Rhai ABORTS on an unbound variable rather than yielding unit, which would give you a verdict that cannot tell a healthy run from a degraded one (the bindings are pushed by `push_degraded_inputs_bindings`, called from BOTH `build_condition_scope` AND `evaluate_expression` — the inline judge evaluates through the second, so binding only the first would have blinded the one gate this exists for); (c) the engine changes **no routing** — as with `__staleness__`, whether a degraded input should fail, abstain (`not_applicable`) or merely annotate is the author's call. The key is engine-AUTHORED: derived from the engine's private results map and graph topology (never read back from module-authored JSON), applied set-or-REMOVE so a module cannot fabricate or inherit one, and stripped from inbound trigger payloads by `strip_engine_authored_keys`. **Note the interaction with #734**: a failed node with no `continue_on_error` and no error edge now FAILS the run, which is the right default — this bullet is about the case where the author has deliberately opted into degrading, and until now that opt-in was silent. Measured on the dev fleet at the time of writing: 12/36 workflows have a multi-parent node, 7/36 a `collect`, but only **3/36** can continue past a node failure at all.
- **Grounding-by-default injection is world-aware (2026-07).** When grounded memory is on (`ENABLE_SMART_MEMORY_CONTEXT`, default), the engine injects `__actor_context__` into a node only if the node consumes memory. Per-node `needs_memory` (graph-json `data`) is honored EXPLICITLY; when ABSENT the default is `false` for pure-egress/send worlds (`http`/`network`/`messaging`) and `true` for everything else (reasoning/compose worlds like `secrets`/`agent`, incl. the `llm-inference` template which is `secrets-node`). So the delivery-pattern "send" leg (http-node) gets NO curated memory by default — closing the exfil surface that `tier1 + egress=public` reopened. A send node that legitimately needs memory sets `needs_memory: true` explicitly. Classifier: `talos_capability_world::world_defaults_no_memory`; gate: `ParallelWorkflowEngine::node_needs_memory_for_world` (both dispatch paths). Reserved keys `__actor_context__`/`__accumulated__`/`__trigger_input__` are ALSO stripped from every inbound trigger/test payload before injection (`inject_actor_context_into_input`) — they're engine-authored and a caller-supplied top-level copy is a context-spoof vector. **Fleet-wide kill-switch:** `ENABLE_ACTOR_CONTEXT_INJECTION` (`talos_config::actor_context_injection_enabled`, default ON) — off ⇒ NO node receives `__actor_context__` (gated at both dispatch chokepoints; assembly at trigger/scheduler/sub-resolver short-circuited too). Distinct from `ENABLE_SMART_MEMORY_CONTEXT` (which only picks smart-vs-legacy assembly and still injects when false).
- When rewriting modules, use `hot_update_module` with `fuel_budget` to recompute max_fuel from actual payload characteristics.

## Code Conventions
- Rust: Follow existing patterns. Use `anyhow::Result` for error handling. Use `tracing` for logging.
- Frontend: React functional components with hooks. Zustand for state. No `dangerouslySetInnerHTML`.
- Environment-aware behavior: Check `config::is_production()` or `RUST_ENV=production`.
- Tests: Don't modify test files unless fixing tests for code you changed.

## Migration Rules
- Never modify an already-applied migration (changes the checksum, breaks sqlx). If an applied migration is buggy, ship a follow-up migration that corrects it — don't edit the original. See `20260414115200` (buggy envelope-split) + `20260414124348` (the actual fix) as an example.
- Always create new migration files with timestamp prefix: `YYYYMMDDHHMMSS_description.sql`
- Use `IF NOT EXISTS` / `IF EXISTS` for idempotency.
- No `CONCURRENTLY` (incompatible with sqlx transaction wrapper).
- For row-level data migrations that may hit malformed rows, use a PL/pgSQL `FOR ... LOOP` with nested `BEGIN/EXCEPTION` per iteration — the nested block creates an implicit SAVEPOINT so one bad row doesn't abort the batch. A bare `DO $$ ... EXCEPTION WHEN others $$` at the outer level catches errors but rolls back everything, silently no-op'ing the migration.

## Architectural Mandate (CRITICAL)

**Workspace topology after the May-2026 spike.** The controller bin is now ~7.3k LoC (down from ~95k); 105 `talos-*` workspace crates own the implementation. The bin is bootstrap (main.rs ~6.4k, lib.rs + ~59 re-export shims under 10 LoC each). Every former top-level module in `controller/src/*` is now a small re-export shim pointing at its canonical home crate; do not write new logic in those shims. When a path like `crate::foo::bar` appears in remaining controller code, treat it as syntactic sugar for `talos_foo::bar` — the dep tree, lints, and ownership belong to the underlying crate.

The MCP handler tree lives in `talos-mcp-handlers` (~65k LoC, 27 source files: 21 handler-domain modules + lib/types/utils/schemas/tests support). The GraphQL surface lives in `talos-api`. Both keep `pub mod` re-export shims at `controller/src/mcp/mod.rs` and `controller/src/api/mod.rs` so existing import paths keep resolving. **When the priority-extraction list below references `mcp/foo.rs`, the actual file is now `talos-mcp-handlers/src/foo.rs` — the work is the same, the path moved.**

**Incremental clean architecture extraction.** MCP handlers must be thin wrappers (~30–50 lines):
1. Parse args → validate → call service → format response.
2. New domain logic → goes in a domain/application service, NOT inline in the handler.
3. Touching an existing handler → extract SQL into a repository method, extract validation into a validator.

**Priority extractions (highest value, do these when touching related code).**
Paths reference `talos-mcp-handlers/src/*.rs` post-extraction (the historical
`controller/src/mcp/*.rs` paths still resolve via the re-export shim).
**Status (2026-05-05, post-r304):** raw-sqlx-in-handlers count is
**0** workspace-wide. The two named LoC monsters from prior sessions
(`handle_replay_workflow_mode` and `handle_add_node_to_workflow`'s
inline-Rust dispatch) are extracted; replay shipped in r303,
inline-compile in r304. Architectural mandate is fully on the
service-extraction track now — the cross-protocol Arc-injected
service pattern (see r295 `ExecutionOrchestrationService`, r302
`WorkflowManifestService`, r303 `ReplayService`, r304
`InlineCompileService` in "Completed extractions") is the canonical
shape: typed input + outcome structs, `thiserror` enum with stable
`jsonrpc_code()` mapping, `user_facing_message()` collapsing
internal errors to a generic message (security: never leak
schema/query details), Arc-wrapped dep injection, single instance
shared across MCP and GraphQL ctx. Remaining structural work below:
- `search.rs` → **DONE.** The embedding pipeline + fallback chain live
  in the `talos-search-service` crate; `SearchService`
  (`new(workflow_repo)` + `search_semantic`) is Arc-injected on
  `McpState.search_service` and `handle_search_workflows_semantic` is a
  thin wrapper (parse/validate → `search_semantic(SemanticSearchInput)`
  → format), with typed `jsonrpc_code()` / `user_facing_message()`
  errors. `search.rs` is raw-sqlx-free. Cross-protocol-ready (no
  GraphQL consumer yet, but the Arc pattern supports one). This
  completes the named-priority extraction list.
- `secrets.rs` → extend `SecretsManager`. Already raw-sqlx-free;
  extraction here is about reconciling the name+namespace vs.
  key_path semantic mismatch in `handle_*`, not pulling SQL. More
  design problem than mechanical extraction — touches the security
  surface, so plan carefully.
- `workflows.rs` → most heavy lifters already extracted (r297/r298/r299
  pure-helper passes + r304's inline-compile lift shaved ~590 LoC
  total across `handle_test_workflow`, `handle_test_workflow_draft`,
  `handle_add_node_to_workflow`). `handle_create_workflow` is now
  ~300 LoC of orchestration; further reduction would be
  diminishing-return helper churn unless a NEW consumer requires it.
  `handle_add_node_to_workflow` is now ~516 LoC (down from ~767);
  remaining content is graph-mutation orchestration that already
  uses helpers — not a structural target.

**Completed extractions (follow the pattern):**
- `AdvancedRepository`, `AnalyticsRepository`, `ExecutionRepository` — repository-per-domain.
- `WorkflowRepository` — 45+ methods. `mcp/graph.rs` handlers use `fetch_graph_json` / `save_graph_json` helpers that delegate here. Tag/embedding methods added 2026-04-16.
- `ActorRepository` — `get_actor_full_summary` (LATERAL join consolidation), approval policies, action log, budget, secret grants, status transitions. `resolve_actor_via_repo` used by all 20+ handlers. `spawn_log_action` + `spawn_log_admin_event` lifted here in May-2026.
- `ModuleRepository` — ref counting, delete/batch-delete, rename, org sharing. Created 2026-04-16.
- `ParallelWorkflowEngine` — dispatcher unification + `build_encrypted_secrets()` helper (consolidates 5-step secret pre-fetch; fixed loop-node dispatch gap 2026-04-16).
- `SubworkflowContractService` — handler extraction model. Use as the template for future thin-handler extractions.
- `LlmClient::with_vault` — vault-first key resolution with env fallback.
- `WorkflowCreationService` (May-2026) — pulled out of `handle_create_workflow_from_description` (1,104 → 173 LoC). Cross-protocol consumer: same service backs MCP and the GraphQL `createWorkflowFromDescription` mutation.
- `HotUpdateService` (May-2026) — pulled out of `handle_hot_update_module` (530 → 78 LoC). Pure-helper-tested transformation logic (`resolve_source`, `wrap_source_with_module_macro`, fuel cascade, world-short mapping); typed `HotUpdateError` enum maps cleanly to JSON-RPC codes.
- `ExecutionOrchestrationService` (r295, May-2026) — pulled out of `handle_trigger_workflow` (493 LoC), `handle_retry_execution` (137 LoC), `handle_replay_execution` (190 LoC), `handle_replay_execution_with_input` (197 LoC) — ~1020 LoC of orchestration across `executions.rs` + `workflows.rs` collapsed into one cross-protocol service. Same `Arc` is consumed by the MCP handlers AND the GraphQL `triggerWorkflow` mutation; one engine builder, one NATS dispatch path, one auth gate. Includes a TOCTOU fix in r296 (`WorkflowRepository::create_execution_under_concurrency_limit` — `SELECT ... FOR UPDATE` + COUNT + INSERT in one transaction). The canonical reference for the cross-protocol service pattern.
- `WorkflowManifestService` (r302, May-2026) — pulled out of `handle_export_platform_state` (87 LoC) + `handle_import_platform_state` (290 LoC). Both handlers became thin wrappers (~9 LoC, ~41 LoC). `ManifestError::user_facing_message()` security invariant: `Internal` collapses to `"Database error"` so the protocol response never leaks schema/query details (locked in by a unit test). Cross-protocol-ready; same Arc can back a future GraphQL mutation. `platform.rs` 1739 → 1429 LoC.
- `ReplayService` (r303, May-2026) — pulled out of two ~340 LoC handlers in `sandbox.rs` (`handle_replay_module_regression` and `handle_replay_workflow_mode`). Both paths share one private `run_replays()` kernel — load-with-template-fallback, secret prefetch, governance/unknown world rejection, and per-row execute-and-diff loop run from one place. Pure-helper `plan_workflow_replay` walks the graph for fan-in detection; testable without runtime. `sandbox.rs` 3822 → 3354 LoC. 18 unit tests cover the fan-in path, capability-world rejection, error code stability, internal-error message redaction, and counter aggregation. Output shape preserved byte-for-byte.
- `InlineCompileService` (r304, May-2026) — pulled out of `handle_add_node_to_workflow`'s `rust_code` branch (~340 LoC of capability check + lint + compile + shared-module guard + permission-drift guard + persistence). Handler 766 → 516 LoC. Pre-compile actor capability check inside the service (saves 30–60 s of compile budget on a doomed request); post-compile defense-in-depth check stays in the handler since it covers BOTH the inline-Rust path AND the `module_id` path. Every operator-recognised error string copied verbatim from the pre-extraction handler — `"Compiled successfully but no WASM bytes were generated"` and friends are locked in by unit tests. 12 unit tests; cross-protocol-ready.

**May-2026 workspace decomposition** (controller bin ~95k → ~7.3k LoC). New crates that own former controller modules whole-cloth:
- `talos-templates`, `talos-llm`, `talos-atlassian`, `talos-slack`, `talos-compilation`, `talos-wit-inspector` — leaf services.
- `talos-integration-helpers` — shared `RenewalFailure` + `looks_like_oauth_failure` for push-notification integrations (breaks the gmail↔gcal coupling).
- `talos-google-calendar`, `talos-gmail` — push-notification stacks per `docs/integration-pattern.md`.
- `talos-continuation-trigger` — approval-gate / suspension dispatch (was `pub(crate)` in mcp::advanced; lifted so webhooks can call it without depending on mcp).
- `talos-webhooks` — inbound webhook router + dispatch chain.
- `talos-api` — entire GraphQL surface (QueryRoot/MutationRoot/SubscriptionRoot, 40 handler files, dataloaders, validation, `TalosSchema` alias).
- `talos-api-docs` — GraphQL Playground + REST docs.
- `talos-ws-auth` — GraphQL-over-WebSocket handshake + auth.
- `talos-mcp-handlers` — entire MCP handler tree (27 source files, ~65k LoC, ~280 tool handlers across 21 handler-domain modules, McpState).
- `talos-audit-event` — shared cryptographic audit-event primitives (the hash-chained, HMAC-signed `AuditEvent` + `ExecutionLedger` + offline `verify_chain`). SINGLE SOURCE OF TRUTH for audit hashing/signing: the worker producer AND the `talos-audit-ledger` WORM consumer both depend on it so the verifier can never drift from the producer. `worker/src/audit.rs` is now a re-export shim.
- `talos-envelope-seal` — RFC 0010 P3 (D3b) controller-side per-execution secret-envelope sealing: `InFlightSeals` (atomic-`take` single-claim), `handle_secret_claim`, `RedisLease` (Lua-CAS), `run_claim_responder` (the single primary `verify()` caller for `SecretClaim`). The crypto (`seal_secrets`/`WorkerEphemeral::open`: ephemeral-ephemeral X25519 → HKDF → AES-GCM) + the `SecretClaim`/`SealedSecrets`/`ClaimResponse` wire types live in `talos-workflow-job-protocol::envelope_seal`; the worker client is `worker::secret_claim`. **Default-OFF** (`TALOS_ENVELOPE_SEALING` unset) is byte-identical to the legacy inline WSK envelope — the `sealing`/`secret_paths`/`claim_inbox` `JobRequest` fields bind into `signing_payload` only when `sealing != 0` and `skip_serializing_if`-omit when default. The dispatch-loop wiring is LANDED + compile-verified: engine (`engine_dispatch_single`) resolves plaintext under the flag → `DispatchJob.plaintext_secrets` → dispatcher registers `InFlightSeals[job_id]` + stamps `sealing=1`/`claim_inbox` → `talos-engine::build_nats_dispatcher` spawns `run_claim_responder` once (OnceLock; NO controller-main change) → worker `execute_job` calls `secret_claim::claim_secrets`. Requires P1 Ed25519 (`TALOS_CONTROLLER_SIGNING_KEY`) to sign SealedSecrets. ALL workflow shapes seal under the flag: single-node + loop-body share `secrets_pipeline::build_dispatch_secrets_for`; **pipelines** seal per step in ONE claim (`dispatch_chain` collects a per-step `Vec<HashMap>` into a single `SealContext::from_bytes` entry; the worker's `execute_pipeline_job` does one `claim_secrets_raw` and feeds step `i` its own map). The worker downgrade guard under `required` is PRECISE — it refuses a `sealing=0` dispatch only when it carries a non-empty WSK envelope (a no-secret node/step decrypts nothing and is allowed). Validated end-to-end over live NATS (`full_claim_loop_over_live_nats` + `full_pipeline_claim_loop_over_live_nats`, both asserting no plaintext on the wire). Canary COMPLETE (2026-07-06): dev stack runs `required` permanently with Ed25519 keys (`TALOS_DISPATCH_SCHEME=ed25519`, static `TALOS_WORKER_PUBLIC_KEYS` fleet identity); the sealed-secret round-trip was proven black-box in `audit` AND `required` by parking a dummy `anthropic/api_key` in the vault so the LLM prefetch made every dispatch secret-carrying — the worker resolved the key from the CLAIMED map (Anthropic returned 401 on the dummy, proving delivery), no-secret nodes still ran under `required`, zero downgrade refusals. Chart enablement runbook lives at values.yaml `controller.env` § TALOS_ENVELOPE_SEALING; both signing keys render as optional bootstrap-Secret refs.

**Good examples to follow:** `ModuleExecutionService`, `AuthService`, `SecretsManager`, `CompilationService`, `SubworkflowContractService`, `ParallelWorkflowEngine`, `ActorRepository::get_actor_full_summary` (LATERAL join pattern), `graph.rs::fetch_graph_json` (helper delegation pattern).
**Anti-pattern to avoid:** Raw `sqlx::query(...)` calls directly inside MCP handler functions. **Down to 0** in `talos-mcp-handlers/src/*.rs` as of 2026-05-04 and held at 0 through r303/r304 (down from 371 → 276 → 0). The lint-equivalent invariant is now: any new handler PR adding raw `sqlx::query` to a `talos-mcp-handlers` file is a regression — push the SQL into the relevant repository crate first. `encrypted_secrets: Default::default()` in any dispatch path is the other regression class.

## Testing Conventions
- **Unit tests exercise real production code.** Don't shadow production logic with a test-local copy (it drifts). Extract the logic into a `pub(crate)` method and call it from both sides. See `SecretsManager::try_llm_keys_cache_hit` + `llm_keys_cache_tests` for the pattern.
- **Stub constructors for test-only deps.** Use `SecretsManager::test_stub_for_cache()` as the pattern — a real struct with a lazy DB pool that panics if touched, so cache-layer tests don't need Postgres.
- **Tests that hit async code** need `#[tokio::test]`, not `#[test]`. `sqlx::PgPoolOptions::connect_lazy` panics outside a Tokio runtime.

## Pre-deploy validation
- **`make lint` enforces structural rules** via `scripts/lint-structural.sh`. 88 checks today (the authoritative, inline-documented list lives in the script; `bash scripts/lint-structural.sh --count` prints the live number, and check 54 fails the lint if this sentence's count goes stale), each tied to a specific past regression so it catches at PR-time the class of bug that survives `cargo check` cleanly but breaks at CI or request time:
  1. raw `actor_memory` writes + legacy `value`-column projections outside `talos-memory/`
  2. bidirectional `controller/src/main.rs` route ↔ `deploy/helm/talos/templates/frontend/configmap.yaml` location alignment (opt-outs: `// no-nginx-route`, `# no-controller-route`)
  3. legacy `__agent_context__` key regressions (canonical is `__actor_context__`; opt-out `// allow-agent-context-key`)
  4. per-call `SecretsManager::new(...)` outside canonical wiring (opt-out `// allow-secrets-manager-new`)
  5. `helm template` clean-render with defaults AND with every `enabled: false` toggled on
  6. raw `sqlx::query*` inside `talos-mcp-handlers/` (opt-out `// allow-mcp-sqlx`)
  7. `cargo clippy --workspace --no-deps -- -D warnings` matching CI (gated behind `TALOS_LINT_CLIPPY=1` because clippy is a 60-90s build; opt in locally for parity at PR time)
  8. `trigger_type` column references against `workflow_executions` schema
  9. boolean-column drift against `workflow_schedules` / `webhook_triggers`
  10. discarded Result on an awaited call — two legs. **(a)** raw `let _ = sqlx::query(...)` anywhere outside tests (the original 2026-05 invariant, opt-out `// allow-sqlx-swallow`). **(b)** widened 2026-08-19 after #658 found `handle_add_node_to_workflow` swallowing a REPOSITORY call — a failed graph save still answered "Node added", and leg (a) structurally cannot see a repository method. Leg (a) reaches **2 of the 109** non-test `let _ = <expr>.await` sites in the workspace. The obvious widening (grep the `let _ =` LINE for `.await`) was built and MEASURED and REJECTED: the house style for the calls that matter is a broken method chain, so **80 of 109 sites span multiple lines**; it sees 3 of the 42 problem sites (7.1%, below the <8% recall bar that already rejected #654's lint), 0 of the 7 that report success on a failed write, and — reinstated by line index — it does **not** fire on #658's own defect. Leg (b) is therefore STATEMENT-aware (gather forward to the terminating `;` at depth 0, in perl) and SCOPED to `talos-mcp-handlers/src/`, where **40 of 41** sites were reported-success-on-failure or silent data loss: a handler is by definition about to answer a caller, so a Result it drops is one nobody will ever see. Same scoping principle as check 6 and check 50. It ships at **zero, not as a ratchet** — all 40 problem sites were converted to `if let Err(e) = … { warn!(…) }` and the one genuine fire-and-forget (`tx.rollback()` on a path already returning an error) carries the marker. Verified in the failure direction three ways: **41** violations against the tree at `911a457`, **42** against the pre-#658 tree, where it names the defect in situ at `workflows.rs:2443` while leg (a) returns **0** on the same files; and it fires on that defect reinstated by line index into the fixed tree. **Stated limits, all in the loud direction:** brace counting is TEXTUAL (a brace in a string literal ends a statement early — a miss — or late — a false positive; cross-validated against an independent Python implementation, `scripts/lint-swallow-inventory.py`, which returns exactly the same 30 sites with no disagreement); the `#[cfg(test)] mod` strip ends at the first column-0 `}`, so an over-run leaves test code in the haystack (false positive, never a silent miss); and it says nothing about `.ok()`, `unwrap_or_default()` on a write, or `let _ =` on a non-awaited Result. The closed 109-site inventory with per-site verdicts is `docs/swallowed-results-inventory.md`. Opt-out `// allow-swallowed-result: <reason>` (leg b)
  11. misleading-success Err-only outbound webhook fires
  12. caller-supplied limit clamp drift (the `.unwrap_or().min()` shape)
  13. chart-wide labels under NetworkPolicy `from:` / `to:` selectors
  14. `talos-api` `Err(async_graphql::Error::new)` missing `.extend_safe()`
  15. `graph_json` writes via canonical chokepoint (MCP-1226/1227/1228/1229)
  16. `wit/talos.wit` ↔ `module-templates/wit/talos.wit` drift
  17. `encrypted_secrets: Default::default()` outside tests — **now also a compiler guarantee** (2026-07-02): `EncryptedSecrets` no longer derives `Default`; the empty case costs a deliberate `EncryptedSecrets::empty()`, so the accidental-empty bug can't compile. The lint remains as a cheap backstop but should find zero sites structurally. (Checks 23 and 39 were evaluated for the same graduation and deliberately kept as lints: 23's no-AAD `encrypt_value` has a legitimate *cross-crate* caller — the `talos-api` secrets-table writers — that Rust visibility can't distinguish from a disallowed one; 39 is a raw-SQL status write, not expressible as a type.)
  18. `JobResult.sign()` in worker must use `sign_with_worker_id`
  19. worker must single-publish each `JobResult` (no dual NATS publish)
  20. every wasmtime WASM proposal must be explicitly opted in/out
  21. integer-cast wraparound (`.as_u64()…as u32` / `map(|i| i as i32)`)
  22. GraphQL queries with sibling mutations must have a scope gate
  23. `encrypt_value()`/`decrypt_value_by_key()` without AAD outside the secrets table
  24. inline control-char predicate in a write surface (use `talos_validation`)
  25. bare-pool queries on RLS tables in `talos-api/src/schema` (must be tenant-scoped tx)
  26. in-flight status literal must include `'resuming'`
  27. `make_interval(<int arg> => $N)` must cast `$N::int` (int4-only pg arg)
  28. OFFSET pagination needs a unique `ORDER BY` tiebreaker
  29. no bare `engine.set_actor_id()` outside the actor-application path
  30. no `CONCURRENTLY` in migrations (sqlx runs them in a transaction)
  31. outbound HTTP response bodies must be read through `talos-http-body` (cap OOM)
  32. `reqwest Client::builder()` must set an explicit `.redirect()` policy
  33. capability-world ranking must use `talos-capability-world`, not a local re-impl
  34. `actor_memory` `value_format` reads must fail loud (MCP-S2 AAD dispatch)
  35. `cargo fmt --all -- --check` (rustfmt drift) — runs by default
  36. `cargo audit` (RustSec advisories) — env-gated `TALOS_LINT_AUDIT=1`
  37. secret-holding structs must redact in `Debug` (no `derive(Debug)` over a plaintext secret)
  38. raw `wasi:sockets` grant (`allow_wasi_network`) must gate on `max_llm_tier` — a tier-1 actor with raw sockets bypasses `allowed_hosts` + the host-fn tier gate and can egress to any public IP (PR #156); opt-out `// allow-wasi-network-no-tier` for Tier2-default actor-less paths
  39. `workflow_executions` status writes must carry a status guard — a bare `SET status='<lit>' … WHERE id=$N` clobbers a row another writer owns (crash-recovery `resuming` claim, terminal re-clobber, the resume `pending` TOCTOU; PR #158/#159); add `AND status NOT IN ('completed','failed','cancelled','resuming')` or use the guarded repo methods; opt-out `// allow-bare-status-write`
  40. SSRF-checked outbound URLs must use the shared safe HTTP client — a file calling `check_outbound_url_no_ssrf` is firing a user-supplied URL, so its reqwest client MUST come from `talos_http_utils::outbound::build_outbound_webhook_client[_with_timeout]` (connect-time `ControllerSsrfResolver` closes the DNS-rebinding TOCTOU the call-time check can't; PR #162); a raw `reqwest::Client::builder()` there is the gap; opt-out `// allow-raw-reqwest-ssrf-checked`
  41. approval-gate token lookups must key on `token_hash`, not the raw token — a file referencing `workflow_approval_gates` must not do a bare `WHERE token = $N` equality (raw-secret byte comparison); the `/approvals/<token>/{approve,reject}` handler + preview look up `WHERE token_hash = sha256_hex(provided)` then constant-time compare the full token (`approval_token_matches`, generated `token_hash` column, PR #217). The check ignores `token_hash`, `state_token` (OAuth CSRF nonce), and `verification_token`; opt-out `// allow-approval-token-raw-lookup`
  42. org-pinned-table creates must run on a tenant-scoped tx — an `INSERT INTO {workflows,actors,secrets}` (the org-setting write) must execute on a `begin_org_scoped` / `begin_personal_org_write` tx, NOT the bare `&self.db_pool`/`db_pool`, so the org-pin RLS WITH CHECK (`org_id = app.current_org_id`) enforces once `TALOS_RLS_SET_ROLE` flips on (RFC 0006 / RFC 0005 S3, PRs #219–#222). A bare-pool create only passes via `unset → permit` (silently un-enforced). Comment lines are skipped; UPDATE/DELETE that don't move `org_id` are out of scope; opt-out `// allow-unscoped-org-write` for engine/system/seeding paths
  43. controller test setup must use the isolated-DB harness, not `init_pool()` — `controller/tests/common::setup_test_context` / `isolated_db_pool` give every test its OWN database (a `CREATE DATABASE … TEMPLATE` clone of the migrated DB, dropped on scope-exit), retiring the global-`DELETE FROM …` shared-state cleanup + the nextest serialization it forced. A test calling `controller::db::init_pool()` connects to the shared `DATABASE_URL` directly — reintroducing the cross-binary flake and writing to the `talos_ctl` TEMPLATE the other binaries clone. Only `env_vars.rs` (which TESTS init_pool's missing-URL path) is exempt; opt-out `// allow-test-init-pool: <reason>`
  44. production in-transit TLS gates must fail closed — Redis/NATS/Postgres/Neo4j prod connections must refuse plaintext URLs at boot (return Err/panic), not warn-and-continue (P1-A; HIPAA §164.312(e)/SOC2 CC6.7 transmission security); each gate tagged `// tls-prod-gate-<name>`
  45. env-KEK in production must be guarded — a production boot with the master key in a plain env var must refuse unless `TALOS_ALLOW_ENV_KEK` is explicitly set, and the guard must fail closed
  46. execution finalizers must accept `'resuming'`, not only `'running'` — a `status = 'running'`-only finalizer guard strands crash-recovery resumes (PR #271); opt-out `// allow-running-only-finalize: <reason>`
  47. append-only audit tables must not gain `CASCADE`/`SET NULL` FKs — the immutability trigger blocks the cascade, making the PARENT row undeletable (#264/#266)
  48. template macro world must match `talos.json` `capability_world` — the `#[talos_*(world=…)]` attribute drives bindgen; a drifted talos.json misdocuments the template's privilege; opt-out `// allow-world-mismatch: <reason>`
  49. integration crates must build HTTP clients via `talos_http_utils::trusted_client` (redirect-none + connect-timeout baked in), no raw `reqwest::Client::builder()`; opt-out `// allow-raw-integration-client: <reason>`
  50. raw `sqlx::query` in `talos-api/src/schema` — **must be 0** (GRADUATED to a hard rule 2026-07-06 after the ratchet burned 117 → 0 across #386/#389/#390/#391/#392 + the workflows finale; same arc as check 6's 371→0 for `talos-mcp-handlers`). Resolver SQL goes in a repository/service crate. Extraction MUST preserve the resolver's executor: scoped-tx sites use conn-taking repo methods (`&mut sqlx::PgConnection` — works for both scoped txs and `UnitOfWork::conn()`; see `ExecutionRepository::decide_execution_approval_scoped`, `WorkflowRepository::insert_workflow_scoped`) with the resolver owning begin/commit; silently switching a `begin_org_scoped`/`begin_user_scoped` query to a repo method on the bare pool drops the RLS backstop (checks 25/42 are the guardrails)
  51. no `talos-workflow-engine` dependency in `talos-*-repository/Cargo.toml` — repository crates are the persistence layer and must not reach UP into the execution engine (`talos-actor-repository` grew the edge to host `apply_actor_to_engine`, moved to `talos_engine::actor_binding` 2026-07; `talos-workflow-engine-core` is deliberately NOT forbidden); opt-out `# allow-repo-engine-dep: <reason>`
  52. silent `row.try_get("col").unwrap_or(<default>)` reads — **WORKSPACE-WIDE, must be 0** (a renamed/dropped/retyped column reads as a silent default instead of erroring). Introduced 2026-07-03 as a ratchet at 526 sites scoped to `talos-*-repository`; **fully burned down 2026-07 (524→0) across all 7 repository crates and GRADUATED to a hard rule** (like check 6 for `talos-mcp-handlers`). **Widened workspace-wide 2026-07-07**: the naming glob missed 62 identical sites in crates that are repositories by ROLE but not by name (talos-secrets-manager 24, talos-module-executions 12, talos-registry 11, talos-schedule-repo 7, talos-integration-state 7, talos-auth 1) — all burned down in the widening pass. Every DB read now propagates schema drift with `?` — read as `Option<T>` (NULL still yields the default, drift errors): `.try_get::<Option<_>, _>("col")?.unwrap_or(default)`, or a typed `FromRow`/`query_as!` mapping. Do NOT re-add a baseline. Read-side twin of check 34. The regex catches BOTH plain and turbofish (`.try_get::<Option<T>,_>("col").unwrap_or`) silent reads without false-positiving the fixed `?.unwrap_or` form. **The multi-line hole is CLOSED as of #661** (sub-leg 52b, a statement-aware perl pass; not a new numbered check, so `--count` stays 70): the old note here said a split-across-lines read was "rare, caught in review" — measured, there were **five**, on a check that reported 0 and had been graduated to a hard rule, the sharpest being `timezone` in the workflow-schedule export row (`talos-workflow-repository/src/workflows.rs:1881`), which silently ran every exported cron in UTC. 52b is mutation-proved in both directions: exactly those 5 on the pre-fix tree, 0 after, and it correctly does NOT flag `talos-registry/src/lib.rs:892` where a `.context(...)?` sits between the two lines. **The `.ok()` spelling is CLOSED as of #662** (sub-legs 52c/52d, one statement-aware perl pass; still no new numbered check, `--count` stays 70). `.try_get(...).ok()` is semantically identical to the `.unwrap_or` form — a renamed/dropped/retyped column reads as `None`, indistinguishable from a SQL NULL, never as an error — and was invisible to both legs above because neither regex mentions `.ok`. #661 measured it at **84** and deliberately did NOT gate it, because gating above zero would have meant re-adding the baseline this check's own rule forbids; #662 burned the population down and the leg follows AT ZERO. **The population was 90, not 84**, and both corrections matter: the line grep misses the **7** sites where the house style breaks the chain after `("col")` and puts `.ok()` on the next line (the same multi-line hole 52b closed for `.unwrap_or`), and falsely counts 1 that is prose inside a #661 comment. So 52c/52d is one pass that strips line comments outside string literals, allows ONE level of nested angle brackets in the turbofish (`::<Option<i64>, _>` — a flat `[^>]*>` stops at the inner `>` and silently misses every such site; the inventory script's own first version did exactly that and under-counted by 8), and lets `\s*` span newlines. Mutation-proved against the ORIGINAL tree, not a synthetic edit: it reports exactly the 90 inventoried sites on the pre-fix copies and 0 after, fires by line index on single-line, multi-line, nested-generic and plain reintroductions, and does not fire on a comment quoting the pattern. The 49 (a)-class sites are inventoried in `docs/swallowed-results-inventory.md` Part 3 — ranked first, the `value_enc`/`value_key_id` reads in `talos-memory`, which are NOT NULL, so a `None` could only ever be projection drift, and `resolve_stored_value` answers that with an EMPTY MEMORY reported as success (its `value_plain` fallback has been dead since Phase B dropped the `value` column). **Stated limit: this is still a CHAIN matcher.** A `try_get` reached through a variable, `.map_or`, and the control-flow `match row.try_get(…) { Err(_) => … }` shape are invisible to it — measured at 0, 0 and **14** respectively; the 14 are per-site judgements (several are that shape used CORRECTLY, e.g. probing an unknown column's type), so a blanket gate there would be wrong.
  53. unguarded wasmtime `Component::new` in `worker/src` — component compilation runs Cranelift codegen IN THE WORKER PROCESS, and wasmtime can PANIC (not `Err`) on certain guest instruction patterns (the aarch64 `value_is_real` lowering bug on jco/StarlingMonkey output; the class is open-ended and per-arch). An unguarded panic unwinds through the whole worker → every in-flight job dies (guest-influenceable DoS). All sites MUST route through `TalosRuntime::compile_component_guarded` (wraps `guard_codegen_panic` = `catch_unwind` → clean per-job error); the one chokepoint is tagged `// allow-unguarded-component-new`
  54. lint self-consistency meta-check — check numbers must be contiguous 1..N and CLAUDE.md's "N checks today" sentence must match `--count` (the count drifted three ways by 2026-07-01: script 49, CLAUDE.md 43, pre-push comment 40)
  55. bare `row.get(`/`r.get(` sqlx reads in DB-layer crates — **must be 0** (a bare `.get` PANICS on NULL/type-drift, killing the tokio task mid-request → caller sees a connection reset; the first workflow-bound webhook's NULL `module_id` took down every `list_webhooks` call this way, #427). The panic-side sibling of check 52 — correct idiom is `try_get(...)?` (same fail-loud, clean error). Introduced 2026-07-08 as a ratchet at 473; **fully burned down the same day (473→0 across all ten DB-layer crates) and GRADUATED to a hard rule**. Scope: repository crates + the check-52 widened family (talos-memory, talos-secrets-manager, talos-registry, talos-module-executions, talos-integration-state, talos-auth) — deliberately NOT mcp-handlers/engine, where `r.get` means serde_json. Do NOT re-add a baseline
  56. engine built with a literal-None effective actor — `with_effective_actor(None, …)` outside the builder makes an unbound workflow run at the engine's Tier-1 fail-safe on that path while manual triggers resolve the default actor (PR #461: 16h of silent scheduled failures; review found the same defect on retry/replay/webhook/continuation). Resolve via `talos_workflow_authorization::resolve_effective_actor` and bind its answer; opt-out `// allow-unresolved-effective-actor: <reason>`. **this change (2026-09-06) removed the last two opt-outs in `talos-mcp-handlers`, and the lesson is about the MARKER rather than the code.** `handle_call_workflow` carried one whose justification text read *"test_workflow's wf-actor-only binding is a documented asymmetry … acceptable for a TEST path"* — `call_workflow` is a production SYNC path the tool docs recommend for inline results, and the marker described a different handler entirely; `handle_bulk_trigger_workflow`'s said the gate plumbing "is tracked as a follow-up". An opt-out is only worth its reason, and neither reason was about the site it sat on. Both now resolve through `crate::utils::resolve_sync_call_effective_actor` — the SAME gate, the SAME `trigger_auth_error_to_response` mapping — ABOVE the row creation, so one value is stamped on the execution row and bound on the engine (the Phase-D2 contract `trigger.rs` has followed since #461). **The consequence was two-sided and measurable**: for an UNBOUND workflow the engine ran at the Tier-1 fail-safe with no tenancy principal (no `__actor_context__`; `__memory_write__` / `__ops_alert__` / `__ml_distill__` all refused for want of an actor; RFC 0012 ledger rows written with `actor_id: null`) while the BEFORE-INSERT trigger `trg_set_default_actor` stamped the user's Default actor on the execution ROW — the row said Default, the engine ran as nobody. **Latent for production, stated plainly**: 6 of 36 workflows on the reference fleet are unbound and every one is a `stress-*` draft (11 executions in 30 days), so no production workflow was affected. **Two behaviour changes, both correct and both new refusals**: the gate can now decline a sync call for an archived/terminated actor, an exhausted execution budget or a capability-ceiling violation on the workflow's own graph — all of which `trigger_workflow` already applied to the same workflow; and passing the resolved actor into `create_execution_under_concurrency_limit` turns on the per-actor advisory-lock budget backstop that both sync paths were skipping with `actor_id: None`. The guard against a revert is this check itself, mutation-proved at both sites
  57. sub-engine built without actor-bind + ceiling narrowing — a sub-engine from `adapter_set().into_engine_with_graph(…)` inherits the PARENT's `actor_id` AND `max_llm_tier`/`max_write_ceiling` verbatim. Two gaps: a sub-workflow bound to a stricter actor silently runs at the looser parent ceiling (the H2 escalation PR #504 closed via ceiling narrowing), AND direct `agent_memory` RPCs inside the sub resolve against the PARENT's actor instead of the sub-workflow's own bound actor — silently disagreeing with the `__actor_context__` injection path (which already uses the sub-actor) and writing memory into the wrong actor (identity axis added 2026-07). Both close at three build sites via the single chokepoint `bind_subengine_actor_and_ceilings` (agent-loop via `resolve_subworkflow_binding` hoisted before the loop). Any non-test file calling `into_engine_with_graph` must reference the binding chokepoint (`bind_subengine_actor_and_ceilings` / `resolve_subworkflow_binding`); opt-out `// allow-unnarrowed-subengine: <reason>` for deliberate parent-context clones. Sub-workflows with NO bound actor keep the parent identity (utility judges/classifiers run in the caller's context). Sibling of checks 29/56
  58. registered-but-never-incremented Prometheus metric (dead metric) — a `TalosMetrics` collector field that is declared + `registry.register()`ed but never mutated stays flat at 0 forever, so any alert/dashboard on it silently never fires (this is exactly how the #570 workflow failure-rate alert would have shipped useless — `talos_workflow_executions_total` had zero `.inc()` sites). For every metric field the check requires a LIVE mutation somewhere in the workspace (`.field … .inc()/.inc_by(nonzero)/.add()/.dec()/.observe()/.set()/.set_to_current_time()`); the `new()` registration + the `.inc_by(0.0)` pre-seed loops use the bare local (no leading dot) so they don't count. **Test code is not production code**: a `#[cfg(test)] mod` region at column 0 is dropped from the haystack, as are whole test-only source files (`src/tests.rs`, `*_tests.rs`, `src/test_support.rs`), so a metric mutated ONLY by a test still reads as dead. That stripping was CLAIMED here (and in the check's own header comment) from the day the check landed but was never implemented — the perl explicitly did the opposite, and the ~90 lines of production code that sit AFTER `crash_recovery.rs`'s test module are why a naive truncate-to-EOF is wrong. The gap was not theoretical: `talos_dek_cache_size` and `talos_module_payload_encryption_failures_total` read as LIVE purely because `talos-metrics`' own `crypto_invariant_metrics_render` unit test touches them — a test written to prove the alerts on them would not silently stop firing — while `TalosDEKCacheOverflow` and `TalosModulePayloadEncryptionFailures` shipped un-fireable for months. Fixed 2026-07-31 (#620) with a region strip that is conservative in the SAFE direction only (a mis-detected region end leaves test code in the haystack — a false negative — and can never swallow production code). Priority order for the burn-down baseline: a dead metric with no alert is debt, a dead metric WITH an alert is a false assurance — burn those first. **Two limits to state rather than imply** (overstating a lint is this same defect one level up): (a) the strip ends a region at the first column-0 `}`, so a multi-line raw string inside a test module ends it EARLY and leaves that module in the haystack — one real instance today, `talos-templates/src/generator.rs`, harmless because the safe direction is a false NEGATIVE; (b) the haystack is TEXTUAL, so an increment wrapped in a helper (`record_outcome`, `publish_dek_cache_size`, `inc_auth_attempt`/`inc_auth_failure`, `inc_payload_crypto_failure`, `inc_secret_decrypt_failure`) reads as live even if NOTHING CALLS THE HELPER — gutting a wrapper body is caught, deleting all its call sites is not (verified by mutation 2026-07-31). Closing (b) needs a call graph, not a grep; the guard for call sites is a per-metric unit test that drives the PRODUCTION path and asserts the counter moved, so ship one with every wrapper-wired metric. The strip carries its own two-direction tripwire, and the OVER-strip landmark must be production code sitting AFTER a `#[cfg(test)] mod` in the SAME file or the assert is vacuous — its first version pointed at `record_workflow_outcome` (above the test mod in `talos-metrics/src/lib.rs`), so a truncate-to-EOF strip left it silent while the check falsely called `crash_recovery_total` dead; it now pins `crash_recovery.rs`'s `record_outcome`. Opt-out `// allow-unincremented-metric: <reason>` on the field's struct-declaration line for a genuinely external/scrape-only collector
  61. signed JSON must be hashed as its EXACT WIRE BYTES — `serde_json`'s f64 round-trip is NOT idempotent (~10% of ordinary computed ratios reparse to a different f64, one ULP off, so `write(parse(write(x)))` differs in content and length). Hashing a signed field as `Sha256(value.to_string())` hashes a form RE-DERIVED on each side: controller hashed `write(x)`, worker hashed `write(parse(write(x)))`, hashes differed, and every job carrying an unstable float failed Ed25519 verification — `pa-autonomy-digest` failed 100% of runs while text payloads passed for weeks (a latent fleet-wide lottery). Normalising to a round-trip "fixed point" was the first fix and is INSUFFICIENT: some floats have no fixed point (`5.455171886890906e-115` cycles forever). **ONE generic type implements the fix for both signed-wire surfaces**: `talos_workflow_job_protocol::RawSigned<T>` — aliased `SignedJson = RawSigned<serde_json::Value>` for dispatch/result payloads, instantiated as `RawSigned<MemoryOp>`/`RawSigned<IntegrationOp>` for the memory / integration-state `Set` ops (#598, the memory-RPC twin, which retired `canonical_json_bytes`/`write_canonical`); `talos_memory::rpc_auth::RawSigned` is a `pub use`, not a second implementation. It carries the exact wire text and hashes it via `raw_bytes()`; construct only via `From<T>` (send side) or deserialization (receive side), and NEVER transcode a message through `serde_json::to_value`/`from_value` (that silently re-derives the bytes — use `to_vec`/`to_string` + `from_slice`/`from_str`). Both surfaces now carry literal wire-format snapshots (`talos-workflow-job-protocol/tests/wire_format_snapshots.rs`, `talos-memory/tests/wire_format_snapshots.rs`: expected JSON + expected MAC hex) — behavioural sign→verify tests cannot catch a CONSISTENT both-sides drift, and the snapshots can. The shared property harness (seeded `arbitrary_json`, the poison-float counterexamples, wire/transcode hop helpers) lives in `talos_workflow_job_protocol::test_support` behind the non-default `test-support` feature; `talos-memory` dev-depends on it. The check fails on a `Sha256`-over-`.to_string()` anywhere in `talos-workflow-job-protocol/src/*.rs` (with or without an intervening `.value()`/`.get()`) AND on any reintroduction of the `canonical_json_bytes`/`write_canonical` identifiers as live code in either crate. Opt-out `// allow-raw-json-hash: <reason>`
  62. the three `build.rs` copies (`talos-mcp-handlers`, `controller`, `worker`) must stamp `GIT_SHA`/`GIT_DIRTY` identically below their `//!` headers — the controller↔worker build-identity handshake compares the `+sha[-dirty]` suffix of two independently-composed version strings, so any drift in how one side derives the sha (`--short=N`, override precedence, dirty rule) makes a SAME-TREE controller and worker disagree and fires the build-skew WARN on a healthy fleet. A shared build-dep crate is not worth ~80 lines with zero runtime surface; this lint is the enforcement the duplication needs (same shape as check 16 for the duplicated WIT file). Opt-out `# allow-build-rs-drift: <reason>`
  63. **ONE Rhai sandbox** — (a) the builder (`talos-rhai-sandbox/src/lib.rs`) must install discarding `on_print` / `on_debug` handlers, and (b) NO other file in the workspace may construct a rhai `Engine`. `rhai::Engine::new()` wires both builtins to `println!`, i.e. straight to the controller's STDOUT and therefore its container logs, and every variable in a workflow expression's scope is upstream-node output (post-interpolation secrets, email bodies). A stored `verdict_expr` / `skip_condition` / dispatch expression of `print(ctx); …` dumps the whole bound context past every DLP boundary; confirmed exploitable 2026-07-29 reviewing `probe_inline_judge`, which takes a CALLER-AUTHORED expression over CALLER-AUTHORED data per request. Discard, never `disable_symbol` — silencing keeps `print` a callable no-op so an expression already containing one keeps evaluating to the same verdict, where disabling turns it into a parse error and breaks a working stored expression on deploy. In-process unit tests cannot observe stdout, which is why (a) is a lint. **Part (b) widened 2026-07-29 (#614)**: fixing one engine wasn't enough — three MORE hand-rolled `Engine::new()` configs existed and had already drifted (the dispatch evaluator ran a 10 000-op cap with NO discard and NO depth/size caps; `testRhaiExpression` had no discard and no `max_map_size`), so the whole config moved into one leaf crate and hand-rolling is now a lint failure. `Engine::default()` counts (rhai's `Default` IS `new()`); `Engine::new_raw()` deliberately does NOT — it registers no StandardPackage and leaves both handlers `None`, so the compile-only sites in `talos-mcp-handlers` (which only call `Engine::compile`, never eval) are correct as-is. wasmtime's arg-taking `Engine::new(&config)` is out of scope (empty parens required). Opt-outs `// allow-rhai-stdout: <reason>` (a), `// allow-raw-rhai-engine: <reason>` (b)
  60. vector-similarity `ORDER BY <col> <=> $N` must carry a unique tiebreaker — duplicate embeddings are NORMAL (the same notification text ingested repeatedly), so a tie is broken by heap order and the top-k CHANGES on identical data; two `ml_eval_model` runs of one model under one policy returned knn macro_f1 0.7065 vs 0.6152 and picked a DIFFERENT backend while the logistic-regression arm was bit-identical, making a promotion gate a coin-flip (worse with `auto_advance`). Check 28's principle in the ANN path; fix `ORDER BY embedding <=> $2, id`; opt-out `// allow-vector-order-no-tiebreaker: <reason>`
  64. every `*/tests/*.rs` integration binary must be named by a CI runner — `docs/backlog.md` claimed "100% of tests/-dir binaries now run in CI — no exclusions" after the June-2026 sweep; it was true on 06-08 and false seven weeks later, because a SWEEP IS A SNAPSHOT, NOT A GATE. 28 binaries had accumulated that no runner enumerated, so they compiled at authoring time and then ran nowhere — including `ml_registry_tenancy_tests`, the only guard on the app-layer `AND user_id = $2` predicate that stops cross-tenant model resolution on the `talos.ml.predict` serving path (RLS does not cover it on a superuser pool), and four per-org-DEK encryption-at-rest binaries whose own headers ASSERTED they ran in CI. Cargo auto-discovers a test target at BOTH `<crate>/tests/<name>.rs` AND `<crate>/tests/<dir>/main.rs` (target `<dir>`) — the check scans both; everything else under `tests/<subdir>/` is a shared module, not a binary, so no hand-maintained exclusion list is needed. Each target must appear in `.github/workflows/quality.yml` or `scripts/test-integration.sh`. Matching is CRATE-QUALIFIED, never by bare name: `wire_format_snapshots` exists in BOTH `talos-workflow-job-protocol` and `talos-memory`, and a name-only match reported the ungated one as covered — that collision is what hid it. Comments are stripped from both runner files first, so a binary mentioned only in prose does not count as gated, and `--test "$var"` loop bodies are skipped so they can't mark a whole crate covered. Three directions fail the check, because "named by a runner" is only worth as much as the runner being real and being run: a FILE with no entry; an ENTRY with no file (a stale entry otherwise blows up 20 min into the integration job with cargo's `no test target named X` — the #567 lesson — while looking like coverage until then); and the runner not being WIRED (`quality.yml` must still `run: make test-integration` and the Makefile target must still invoke `scripts/test-integration.sh`, or every CTRL_TESTS/TC_TESTS entry reads as gated while running nowhere — the original defect one level up). A stale `ci-ungated` marker on a binary that IS gated also fails. Opt-out `// ci-ungated: <reason>` — but do NOT gate a test that early-returns without a provider (`embedding_determinism`): a green check over zero assertions is worse than an honest exclusion.
  59. email-sender template Subject must route through the RFC 2047 encoder — a module-template `template.rs` that interpolates a raw `Subject: {}` header from an un-encoded string mojibakes non-ASCII subjects (an LLM em-dash `—` double-encoded to `Ã¢Â€Â"` in the delivered header — the 2026-07 send-module bug; un-fixable in place because the module was a source-less DB blob). Any template that builds a `Subject: {` header line MUST also call `encode_subject(` (RFC 2047 `=?UTF-8?B?..?=`; ASCII passes byte-identical). A shared helper CRATE is impossible (the compile service regenerates a fixed Cargo.toml, mounts only the single template source, rejects path deps — so `send-html-email` + `send-gmail` each carry their own copy); this lint is the enforceable equivalent. Opt-out `// allow-raw-subject: <reason>` for a genuinely ASCII-only pinned subject
  65. the dev Prometheus must actually observe Talos — the local observability stack observed NOTHING of Talos and loaded ZERO alert rules while looking fully configured (2026-08-02). Every `talos_*` series lives in the CONTROLLER, and `observability/prometheus/prometheus.yml` had no controller job at all; `rule_files: ['alerts.yml']` named a file `docker-compose.yml` never mounted, and because Prometheus treats every rule_files entry as a GLOB, a literal path matching nothing expands to zero files **with no error** — `/api/v1/rules` returned `{"groups":[]}` on a stack whose config listed a rules file; and the worker job was wrong three ways at once (host `talos-worker` does not resolve — the compose SERVICE is `worker`; port 9091 vs the real `METRICS_PORT` default 9090; bearer `dev-metrics-token` vs the real `METRICS_AUTH_TOKENS` default `dev-token`). Net: the detectors added by #618/#620/#623 could not be exercised locally before shipping. Four directions, run over a rule-file set **derived** from `rule_files` + the compose mounts (never a hardcoded list — a third rule file, mounted and named, is scanned automatically; only the canonical chart file is named explicitly because it ships via the PrometheusRule whether or not dev mounts it): **(a)** every `up{job="X"}` an alert selects on must be declared as a `job_name: X` in prometheus.yml (derived from the ALERTS, not a hardcoded list, so a new alert that selects `up{job="…"}` for an unscraped job fails), and the controller job must scrape `/metrics/prometheus` — NOT `/metrics`, a different authenticated dashboard route; **(b)** every `rule_files` entry must resolve through a compose bind mount to a file that exists (config entry → mount → disk), **separately in EVERY compose file that mounts the shared prometheus.yml** — first-match was the original shape and it passed the very tree that motivated the check; the mount may be of the FILE or of any ANCESTOR DIRECTORY (directory mounts became the house style on 2026-08-03 — see check 66 — and resolving only exact file mounts would have failed the fix for that bug), and it **must be `:ro`**; **(d)** no alert name may be defined in more than one mounted rule file — Prometheus does not dedup by name, so two definitions become two rules that fire together and Alertmanager cannot merge them when the label sets differ (found live 2026-08-02: `TalosWorkerDown` existed in BOTH rule files with `for:` 1m and 2m, invisible while `docker-compose.yml` mounted nothing, and both copies were observed `firing` on one worker outage the moment both files were mounted; the dev copy was deleted, the canonical chart definition kept); **(c)** every `talos_*` **or `wasm_*`** metric named in an alert **expression** must be registered — the read-side twin of check 58 (58 = registered-but-never-incremented, 65(c) = alerted-but-never-registered). Only `expr:` blocks are scanned, since comments and annotation prose mention crate paths like `talos_auth`/`talos_metrics` that are not series. **Evidence differs by prefix**: `talos_*` accepts a quoted string in any `.rs` file; `wasm_*` accepts ONLY an OTEL instrument declaration in Rust, translated the way the exporter translates it (`.`→`_`, and `_total` appended to every monotonic counter **unconditionally** — `opentelemetry-prometheus` does not check whether the name already ends in `total`, so `wasm.executions.total` exports as `wasm_executions_total_total`, verified empirically and pinned by `exported_prometheus_names_are_stable_and_idle_seeds_at_zero` in `talos-worker-runtime`). Refusing a quoted literal for `wasm_*` is what excludes `worker/src/bin/metrics_demo.rs` — a demo binary serving its own private `Registry::new()` that nothing scrapes — WITHOUT a hardcoded path exclusion. The canonical `deploy/helm/talos/files/alerts.yaml` is **bind-mounted, never copied**, into the dev stack — a second copy is the drift this closes (`deploy/observability/alerts.yaml` symlinks it for the same reason). **Seven limits, stated rather than implied** (overstating a lint is check 58's own lesson one level up; every one below was proven by a mutation, not inferred): (1) **(b) is per-stack, and had to be made so during review** — as first written it stopped at the FIRST compose file providing a mount, so run against the pre-fix tree it PASSED (`docker-compose.observability.yml` mounted `alerts.yml` while `docker-compose.yml` did not): the gate would not have caught the bug that motivated it. It now requires EVERY compose file that mounts the shared `prometheus.yml` to provide EVERY `rule_files` entry, and validates each stack's own host path; the residual limits are that it inspects only the two compose files named in `PROM_COMPOSE` and only recognises the short `- ./host:/container[:ro]` bind syntax (long-form/`extends`/interpolated mounts read as missing — the safe direction); (2) **(a)** matches only the literal single-line double-quoted `up{…job="X"…}` — a job selector on a non-`up` series, `job='X'`, or one split across lines of a block scalar is invisible, and it never checks that a declared target RESOLVES (`up == 1` is the live stack's job, not the lint's); (3) the controller `metrics_path` probe is scoped to that job's OWN block (`job_name` line → next `job_name`); it was a fixed `grep -A12` window until the 2026-08-02 review, which mutation proved exploitable in the UNSAFE direction (controller on `/metrics` + a neighbour job on `/metrics/prometheus` passed); (4) **(c)** treats any quoted `"talos_x"` in any `.rs` file as proof of registration **including test files and test modules — which check 58 strips and 65(c) does not** — so a metric named only by a test reads as registered; PROVEN by mutation 2026-08-02 (an alert on `talos_only_named_by_a_test_total` failed, then passed once that literal was added inside a `#[cfg(test)] mod` and nowhere else). A runtime-assembled name reads as unregistered, which is the safe direction — and so would an OTEL instrument declared with dots (`talos.foo.total` → exported `talos_foo_total`); (5) three more holes proven by mutation and left open deliberately: a **glob** `rule_files` entry is REJECTED by (b) though Prometheus supports it (false positive, loud); an **extra scrape job** no alert selects on is unchecked, so a second controller job under a different name hitting `/metrics` passes; and **mount MODE was never checked**, so a rule file bind-mounted `:rw` instead of `:ro` passed — **closed 2026-08-03**, (b) now requires `:ro` on every resolved rule-file mount (the mode gap on NON-rule mounts is covered at runtime by `make observability-verify` leg A, which fails any read-write bind on the Prometheus container). (6) **(c) covers `wasm_*` as of 2026-08-02** (this was previously the stated gap: the 11 dev-stack alerts got no coverage from any direction, and SEVEN of them named a series the worker cannot emit — they had been written against `metrics_demo`'s fabricated names). Run against the ORIGINAL tree the extension fails on six real defects (`wasm_memory_used_bytes`, `wasm_cache_hits`, `wasm_cache_misses`, `wasm_errors_total`, `wasm_retries_total`, `wasm_executions_total`), not on a synthetic mutation. Residual `wasm_*` limits, all four proven by mutation 2026-08-02: an OTEL declaration counts as evidence **from any crate and from inside a `#[cfg(test)] mod`** — "evidence must be an OTEL declaration" constrains the CONSTRUCTOR FORM (which is what excludes `metrics_demo.rs`'s raw `prometheus::Counter`s), NOT the location, so `.u64_counter("wasm.ghost")` in a test module anywhere vouches for an alert on `wasm_ghost_total`, the OTEL-side twin of limit (4); the `_bucket`/`_sum`/`_count` strip runs BEFORE the prefix split and ignores instrument KIND, so an alert on `wasm_executions_total_sum` — a `_sum` no counter exposes — passes by stripping to a registered counter name (applies to `talos_*` too); evidence requires the constructor and the name on ONE line (a rustfmt split reads as no declaration — safe direction); `.with_unit(...)` is NOT modelled, so a future unit suffix would make the derivation stale in the UNSAFE direction (the pinning test is the tripwire, not the grep); and a `wasm_*` series registered directly into the default `prometheus` registry rather than through OTEL reads as unregistered (false positive, loud, use the opt-out). (7) **(a) scans the WHOLE rule file, not just `expr:` blocks** — a job name written out in a comment or annotation counts as selected and must then be declared. Tripped over live 2026-08-02 by a comment explaining this very check; false-positive direction, so documented rather than narrowed. Opt-out for (c) only: `# allow-unobserved-metric: <reason>` where **the reason text must NAME the series** (trailing `*` = prefix wildcard) — placement is irrelevant, the marker is matched file-globally, and one naming no `talos_*`/`wasm_*` series excuses nothing (`talos_backup_drill_*` is a node_exporter textfile written by `scripts/drills/backup-restore.sh`); **no opt-out for (a), (b) or (d)** — a job an alert needs but nothing scrapes, a rules file resolving to nothing, and one alert name defined twice each have no legitimate form. **Skip-blinding guard (2026-08-03):** `$PROM_CFG` is a hardcoded path, so any move of `observability/prometheus/` used to turn the WHOLE check into a `⚠` + exit 0 — mutation-proved by renaming it to `observability/prom-conf/` and updating both compose files consistently, a legitimate refactor that silently disabled legs (a)-(d). A missing `$PROM_CFG` is now a FAILURE whenever a compose file still declares a `prometheus:` service; it only skips when the dev stack genuinely has no Prometheus. Deriving `$PROM_CFG` from the compose mount is the real fix and is still open
  66. compose must bind-mount the DIRECTORY, never the tracked FILE — **a single-file bind mount can leave the container serving the new file's bytes TRUNCATED to the old file's length** after the host file is replaced, silently: no error, no log line, no unhealthy container. Git replaces rather than rewrites in place (verified — every `git checkout` of a changed file yields a new inode); atomic-saving editors do the same. **What was OBSERVED** live 2026-08-03, after it had already cost a cycle: #625 merged, deployed, its alert on disk, and `/api/v1/rules` still reporting the pre-merge 13 groups / 37 rules with `WASMMetricsPipelineDead` ABSENT. Host rules file 21953 bytes; `docker exec stat` said 6464; the bytes served were a **byte-exact 6464-byte prefix of the CURRENT host file**, cut mid-word inside a comment. Two independent confirmations that it was a prefix of the NEW file rather than the old file intact: `cmp` against `head -c 6464` matched, and that prefix names `WASMMetricsPipelineDead` exactly once — the live count — where the previous committed version names it zero times; and 6464 is exactly the previous committed version's byte length. It parsed only because the cut landed inside a comment block — mid-value it would have failed loudly and been found in minutes instead of surviving three merges. The same shape would truncate `prometheus.yml`, silently dropping scrape jobs off its tail. So the failure is **corruption, not staleness**. **The MECHANISM was then REPRODUCED deterministically** (2026-08-03, Docker Desktop 29.6.2 / VirtioFS; five independent rigs plus a 26-hour-old container, after two earlier attempts failed). The trigger is the host file acquiring a **new inode**: while a file is edited IN PLACE the mount tracks it correctly and indefinitely (measured 100→301→701→1201 bytes); the FIRST replacement freezes the container's cached SIZE at its last-known value permanently (observed frozen 26 h, unrefreshed by later writes, replacements, re-reads or elapsed time); the DATA path keeps resolving by NAME, returning the current bytes and `ENOENT` once the host path is gone. Net: current content clamped to the frozen size — longer file → the byte-exact prefix above, shorter file → `stat` lies but reads are complete. **Do not restate this as "a single-file mount pins the inode"** — the data demonstrably came from the NEW file, so an inode pin is precisely what did not happen; only the ATTRIBUTES are stale. Note a same-length or in-place replacement cannot exhibit the bug and will "prove" the mount works — which is exactly how the first two reproduction attempts came back negative. `POST /-/reload` does NOT help (it re-reads the same truncated view; the dev stack did not even have `--web.enable-lifecycle`); `docker restart` DOES clear it, no recreate needed, so `prometheus_data` is never at risk. **The rule is a large reduction, NOT a proof**: a DIRECTORY mount resolves each child by name at access time and was correct in every equivalent test — across rename-over, unlink-recreate, kill+start, and on a container that had been up four days — but ONE directory-mounted container was observed frozen across two replacements and could not be made to repeat it. So the mount style removes a deterministic, every-time failure and leaves a rare one; the actual protection is the LIVE check (`make observability-verify`), which compares content and fires on the symptom whatever caused it. A directory mount also exposes EVERY file in that directory, so a mounted directory must contain only what the container should read (this is why `observability/rules/` exists, why `alerts_test.yml` deliberately stays OUT of it — it is a promtool fixture Prometheus would fail to parse — and why `observability/` itself is unmountable: `grafana/provisioning/datasources/` lives under it). Scope: git-TRACKED sources only (an untracked/generated file is not replaced by git); short bind syntax only (long-form reads as absent — the safe direction); `./relative` host paths only. **Stated limits**: (a) this is STATIC — it proves the mounts are shaped right; it cannot prove the RUNNING container reads current bytes, since a container started before the fix still serves stale content through a now-correct compose file. That half needs a live stack and is `make observability-verify`, deliberately NOT a lint, because a CI lint with no stack could only skip and a check that skips is not a gate. (b) only three compose files are scanned; `docker-compose.override.yml` is excluded as gitignored and per-developer, so a single-file mount added there is invisible (same shape as check 65's `PROM_COMPOSE` limit). Opt-out `# allow-single-file-mount: <reason>`
  67. the fleet heartbeat must not reach the identity trust boundary — a NATS `WorkerHeartbeat` is HMAC-signed under `WORKER_SHARED_KEY`, which is **fleet-shared**, so any process holding that key can mint one naming any `worker_id`; a #631 liveness ping is an **Ed25519 proof of possession** of that worker's own registered key. The two look alike and are worlds apart as evidence. If the fleet-view code could write `worker_identities.last_liveness_at`, any shared-key holder could keep any worker's signing key trusted forever and the identity reaper would never act — the unbounded-trust gap #631 exists to close, reopened by an observability feature, and the temptation is specific ("the heartbeat already proves it is alive, why also ping over HTTP?"). Two directions, both scoped to `talos-worker-fleet/`: **(a)** no non-comment source line may name `last_liveness_at` / `touch_liveness` / `worker_identities`; **(b)** its `[dependencies]` may not include `sqlx`, `talos-worker-identity-repository` or `reqwest` — (a) alone is defeated by a helper in another crate, so the dependency edge is cut too. Comments are exempt because the crate documents the rule at length and a rule you may not explain is worse than none. **Stated limit**: this is a TEXTUAL grep over one crate, so a write performed through a re-exported alias, or from a DIFFERENT crate holding an `Arc<WorkerManager>`, is invisible to it — the dependency leg is what makes that hard rather than impossible, and the in-crate unit test `heartbeat_never_touches_the_trust_boundary` is the second copy (a test can be deleted in the same commit that introduces the write; this gate cannot). No opt-out.
  68. catalog template compiles must route through `talos_compilation::CatalogTemplate`, and a template-ROW compile must forward its `dependencies` — `talos.json`'s `dependencies` field is the ONLY dependency declaration the RUNTIME reads for a catalog template, and until 2026-08-11 **six** paths compiled one while only ONE forwarded it: the disk seeder (every controller boot), the `publish-templates` OCI publisher, `restore_pinned_modules`, — via a `modules.dependencies` column the seeder never wrote — `compile_template`, and **`talos-api`'s `createModuleFromTemplate`**, which resolves the same row through the same `registry.get_template_for_user` as its MCP twin and passed `None` where the twin passed `template.dependencies.as_ref()`. Three shipped templates therefore failed to compile at EVERY boot (`briefing-html-generator`/`google-calendar-list-events` on `chrono`, `create-calendar-event` on `urlencoding`), their `wasm_bytes` stayed NULL so they could not run at all, and `make check-catalog` was green the whole time **because it read the manifest** — the gate-that-doesn't-gate class again (#624, checks 64/65). **The sixth path is the one that matters most as a lesson**: while `modules.dependencies` was NULL for all 75 catalog rows the MCP and GraphQL twins were equally, invisibly broken; the moment the seeder started POPULATING that column the same template compiled under MCP and failed E0433 under GraphQL. Fixing the class converted a uniform bug into a protocol-dependent one, inside the change whose thesis was that patching a site is not fixing a class — and neither leg (a) nor (b) could see the file, which contains neither `module-templates` nor a manifest read. `CatalogTemplate` is the one reader of a template dir, carrying source + declared deps as a unit; `CompilationService::compile_catalog_template` consumes it; the dependency-less `compile_to_wasm(user, job, name, source)` convenience was DELETED so the footgun cannot be re-acquired. Four directions: **(a)** a parsed manifest's `"dependencies"` key may be read only in `talos-compilation/src/catalog.rs` — receiver-scoped to names CONTAINING `meta`/`manifest`/`tpl`/`talos_json` (so `template_manifest` and `manifest_json` are covered) in both the `.get("dependencies")` and `["dependencies"]` spellings, so caller-supplied `args.get("dependencies")` is not swept up; **(b)** any non-test file that resolves a catalog dir (`module-templates`) AND calls into the compiler must name `CatalogTemplate` — "calls into the compiler" is `compile_*wasm`/`compile_catalog_template`, so `compile_js_to_wasm` and `compile_python_to_wasm` count (the original literal `compile_to_wasm` grep missed both); **(c)** the deleted convenience must stay deleted — scanned across ALL of `talos-compilation/src/`, not just `lib.rs`, and tolerant of a generic parameter list, because both were trivial evasions; **(d)** a `compile_to_wasm_with_config` call in a file that resolves a template row via `get_template_for_user` must mention `dependencies` in its (paren-balanced) argument list. **Stated limits, every one confirmed by mutation rather than inferred**: all four legs are TEXTUAL — (a) is defeated by a receiver naming none of the four stems (`j.get("dependencies")`) or by any indirection through a variable; (b) by resolving the catalog dir through a constant in another file, and it fires on the FILE not the call, so an opt-out there also blinds it to a future catalog compile added to that file (`talos-mcp-handlers/src/workflows.rs` carries one — its `module-templates` read is a display-name lookup and its compile is caller-supplied bundle source); (c) pins one IDENTIFIER, so a differently-named dependency-less convenience (`compile_simple`) is invisible; (d) is scoped by an ADJACENT string, so a row resolved through a NEW repository method, or in a different file from the compile call, is invisible, and it only proves the TOKEN `dependencies` appears — `dependencies: None` would satisfy it. No leg can prove the forwarded VALUE is right, only that it is forwarded (`catalog_template_tests` covers the value, `scripts/check-catalog.sh` covers the templates). The check was run against the ORIGINAL broken tree and against five evasions (`template_manifest.get`, `manifest["dependencies"]`, `compile_js_to_wasm`-only, a generic `compile_to_wasm<'a>`, and the convenience defined outside `lib.rs`) — all six fail it. Opt-outs `// allow-raw-catalog-deps: <reason>` (a), `// allow-uncatalogued-compile: <reason>` (b), `// allow-depless-compile: <reason>` (d, on or within 8 lines above the call, for a compile of caller-supplied source with no template row behind it).
  69. unconfigured tracing must mean DISABLED — `talos_trace::init_tracing(name, None)` is documented to build no exporter, and BOTH binaries made that path unreachable with `env::var("JAEGER_ENDPOINT").ok().or_else(|| Some("http://localhost:4317"))`. Nothing sets `JAEGER_ENDPOINT` — not docker-compose, not the Helm chart (verified against `helm template`, not the values file) — so every controller and worker built a batch span processor aimed at its OWN container's localhost, failed every export, and logged `BatchSpanProcessor.ExportError` per flush while the Jaeger it could have reached at `jaeger:4317` sat empty for 36 h. **An ERROR that fires forever on a healthy fleet is the harm** — it trains operators to ignore ERROR, days after #646 shipped the transport that will deliver real alerts. Two legs, because either alone is trivially evaded: **(a)** a non-test file that CALLS `init_tracing(` must also name `endpoint_from_env` — the "chokepoint that misses a site" guard, since the defect was byte-identical in two binaries and repairing one would have made it per-binary; **(b)** the three endpoint env vars (`JAEGER_ENDPOINT`, `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_ENDPOINT`) may be READ only in `talos-trace/src/lib.rs`, so a new site cannot re-derive the endpoint — and re-add a default — in a file that never mentions `init_tracing`. **Stated limits, demonstrated not asserted:** both legs are TEXTUAL, so a caller handed an already-resolved `Option<String>` by a third crate satisfies (a) while (b) never sees an env read — invisible to both, as is an endpoint taken from a config struct or CLI flag; (a) fires on the FILE not the call, so its one opt-out (`worker/src/bin/observability_test.rs`, a hand-run demo where localhost genuinely IS the Jaeger) also blinds that file to a future `init_tracing`; (b) matches literal names, so a runtime-assembled var name evades. Neither leg can prove the resolved VALUE is right — only that it came from the one function whose unset-⇒-`None` behaviour is unit-tested. Run against the ORIGINAL tree it fails on all three real sites. Opt-out `// allow-hardcoded-trace-endpoint: <reason>`.
  70. a write keyed on the non-tenant half of a composite `UNIQUE (tenant_col, X)` must also constrain `tenant_col` — #656's `restore_pinned_modules` read under `begin_user_scoped` + `pm.user_id = $1` and then wrote `UPDATE modules SET wasm_bytes = $1 … WHERE name = $2` with NO owner predicate. **The severity turned entirely on a SCHEMA fact the statement does not show you**: `modules.name` is unique only PER USER (`modules_user_name_uniq (user_id, name) WHERE user_id IS NOT NULL`), so "3 of YOUR pins restored" wrote 3 × every tenant holding those names, clobbering any other tenant's `hot_update_module` customisation. A `WHERE <natural key> = $N` looks perfectly ordinary; only the index definition says it addresses more than one tenant's row, and this check reads that definition for you. The table→(tenant col, natural col) map is **DERIVED from `migrations/`, never hardcoded** (hardcoded lists rot — #624): `CREATE UNIQUE INDEX`, inline `UNIQUE(...)` and composite `PRIMARY KEY(...)` inside `CREATE TABLE`, and `ADD CONSTRAINT … UNIQUE`, with `ALTER TABLE … RENAME TO` / `RENAME COLUMN` applied — 22 tables / 26 combinations today, and the rename handling is load-bearing (`actor_memory`'s `UNIQUE (actor_id, key)` is declared on `agent_runtime_memory (agent_id, key)` and is invisible without it). **This check was measured before it was written, not after** — the last three cycles each built a guard and rejected it on evidence (#654's had <8% recall on its own motivating bug; #655's `Capped<T>` could be satisfied while the bug survived; #656's `Previewed<T>` would have been honoured while all three of its bugs survived). Measured here: **0 fires on production code**, and it fires on the #656 defect reintroduced by a line-indexed mutation that was proven to land. **Stated limits, each confirmed by mutation rather than inferred:** it is TEXTUAL, so SQL assembled with `format!()` is invisible; the statement window is the enclosing string literal truncated heuristically, and `//` comments are stripped first because a doc comment quoting `INSERT INTO secrets (…, created_by, …)` otherwise reads as a statement (one real instance, `talos-workflow-repository/src/templates.rs`); an alias-qualified column IS handled (`WHERE m.name = $2` fires) but only for a single-segment alias; a partial-index conflict arbiter (`ON CONFLICT (name) WHERE user_id IS NULL`) counts as constrained, which is the correct catalog idiom in `talos-registry`; and it proves a tenant column is CONSTRAINED, never that it is constrained to the RIGHT tenant — `WHERE name = $1 AND user_id = $2` passes whatever `$2` is (cross-org injection is checks 25/42's business). Test files are excluded deliberately: `talos-advanced-repository/tests/scratch_rls.rs` and `talos-db/tests/rls_org_isolation.rs` issue unscoped deletes to PROVE RLS blocks them, and firing there would be backwards. Opt-out `// allow-untenanted-natural-key: <reason>` on or within 8 lines above the write.
  71. the graph-node-id → UUID mapping must have exactly ONE implementation — `execution_events.node_id` does not carry the graph's string node id, it carries what `talos_workflow_engine_core::engine_node_uuid` derives from it (verbatim if it parses as a UUID, else the first 16 bytes of `SHA-256(id)` as raw UUID bytes — deliberately NOT `Uuid::new_v5`, which rewrites the version/variant nibbles and would orphan every row already on disk). #693 made that function the single WRITER and left the READERS forking the arithmetic: **7 private copies** (`talos-mcp-handlers/src/executions.rs` ×4, `analytics.rs` ×2, `talos-failure-analysis-service/src/lib.rs` ×1), plus a test that pinned the map against its own re-derivation instead of against observed rows. **The failure mode is what makes it lint-worthy: a drifted copy does not error, panic, or log — its join matches zero rows, and zero rows renders as "no problems found"** on the node-failure breakdown, the execution trace, and the failure analyser's label resolution. Detection is by SHAPE, not string: a `Uuid::from_bytes|from_slice|from_bytes_le|from_u128` construction with a `Sha256::digest` in the 8 lines above (the whole idiom is four lines, so a reformatted or renamed copy still fires). **Verified by running the check against the pre-fix tree: 8 findings — the 7 production copies plus the test copy — and 0 on the fixed tree.** Stated limits: it is TEXTUAL and window-bounded (a copy that routes the bytes through a helper, or spreads digest and construction >8 lines apart, is invisible); it cannot distinguish a node-id derivation from any other Sha256→UUID of the same shape, and two deliberately-independent ones exist (gcal's `oauth_account_id`, talos-google-cloud's `derive_provider_key`, both keyed on Google's immutable ACCOUNT id) and carry the opt-out; tests are NOT exempt, because a test that re-derives its own expected value passes even when production and test drift together — pin against ids read out of a live events table instead. The token-hash sites in `mcp-handlers/auth.rs` and the WASM content-hash sites (`modules.rs`/`sandbox.rs`) format their digest as hex and never build a `Uuid`, so they are out of range by shape. Opt-out `// allow-adhoc-node-uuid: <reason>` within 12 lines above the construction (wider than the detection window on purpose — a permanent exemption deserves a paragraph).
  72. personal-information markers must not appear ANYWHERE in the tracked tree — this repository is PUBLIC, and `.githooks/pre-commit` §4 scans `git diff --cached -U0 | grep '^+'`: **STAGED ADDED LINES ONLY**. That is the correct shape for a commit-time gate ("don't let me add this"), but it has a permanent blind spot — anything that landed before the hook existed, or before a term joined the operator-local marker list, is never staged again and so is never re-examined. It sits in a public repo indefinitely, invisible to the only tool built to catch it. **Not theoretical: two markers were live on main across three files when this check was written** (`docs/security/ai-injection-audit-2026-07-20.md`, `talos-workflow-engine/src/engine_dispatch_single.rs`, `talos-workflow-engine/src/oauth_reauth.rs`), and #697 removed a third — all three found by accident during unrelated work, one per session, which is not a discovery mechanism. This check scans the whole tracked tree (`git grep -F -f`) instead of a diff. **It is a LOCAL lint, not a CI check, and that is a measured conclusion rather than a convenience**: the marker list is uncommittable by construction (it *contains* the terms it guards), so CI cannot read it, and every generic stand-in pattern was measured against this tree and rejected — "an email address in source" gives 263 email-shaped tokens across 48 domains, 127 outside `example.com` and every one legitimate (docs, fixtures, vendored `Cargo.toml` authorship, and `talos-dlp-provider`'s redaction tests, which must contain email shapes to test that they get redacted), catching **0 of the 2 markers actually present** because neither is email-shaped; "a UUID in source" gives 65 distinct non-zeroed UUIDs for 1 true positive (~1.5% precision); "an `oauth/` path containing `@`" gives 10 hits, none a marker. Shipping any of those would look like enforcement while catching nothing, so none is offered. **Absent-file behaviour is SKIP, LOUDLY** — a distinct yellow ⊘ line and no green tick, because hard-failing would make `make lint` unrunnable for every public contributor while silently passing would print "clean" to mean "I did not look"; an emptied-but-present list skips the same way, and the success line states the pattern count so a shrinking list is visible. **Output is value-free by construction** (findings are `file:line (marker #N)`, matched text never echoed, and a path that is itself a marker hit has its basename redacted) — a CI log and a pasted lint failure are as public as the repo. **Deliberately NO opt-out comment**, uniquely among these checks: the opt-out would have to sit next to the value it exempts, permanently publishing the thing the check exists to remove. The only resolutions are a placeholder (`user@example.com`, a zeroed UUID) or narrowing the marker list. Verified by running the check against a clean `git archive` of `origin/main`: **3 files reported, exactly the known set**, and 0 on the fixed tree. Runtime 0.07s. **Stated limits**: it scans the TREE, not HISTORY (`git grep` with no revision reads the working tree) — green means "no marker is in the checked-out files", NOT "no marker is anywhere in this repo"; every removed value stays reachable in the commit that removed it, this one included, and purging that needs a separate force-push rewrite (#697 recorded the same caveat). Tracked files only (untracked is the pre-commit hook's moment), fixed-string/case-insensitive/substring (an over-broad marker must be narrowed in the list, since there is no exemption), binaries skipped. The pre-commit hook stays staged-only on purpose — a commit-time failure should be about YOUR change, not about pre-existing tree state; whole-tree inventory belongs at pre-push/`make lint`, where every other structural check already runs.
  73. an env-var PRESENCE test must treat an EMPTY value as unset — `std::env::var("KEY").is_ok()` returns TRUE for `Ok("")`, so a Helm `values.yaml` placeholder (`talosMasterKey: ""`) or a shell `export FOO=` reads as CONFIGURED while every consumer in this workspace treats empty as absent (`talos_config::get_env` falls to its default, `read_env_or_file` falls to `<VAR>_FILE`). **This class had been repaired ELEVEN times under distinct tickets (MCP-590/591/592/597/598/599/611/615/620/621/625) with no structural guard, which is exactly why it kept coming back.** MCP-625 is the canonical writeup — four `security_audit` key checks reported "TALOS_MASTER_KEY is configured" and awarded +15 while `kek_provider` refused the empty key, so "operators saw a green dashboard while critical security primitives were disabled" — and its fix was an INLINE CLOSURE, which is why it did not generalise: when this check was written `handle_security_audit` **still contained an instance of the bug 130 lines below the comment describing it**, grading the platform's CORS posture, and `worker/src/metrics_server.rs` carried the shape MCP-932 had removed from a sibling handler in the same file. Two legs, both chosen so the value is PROVABLY never inspected: **(a)** a presence predicate (`.is_ok()`/`.is_some()`/`.is_err()`/`.is_none()`) terminating an env read, exempt when the chain carries an emptiness or value guard (`is_empty`/`.filter(`/`.trim(`/`unwrap_or`/`map_or`) — those either handle empty or read the value, so empty lands in the same branch as unset; **(b)** a WILDCARD discard (`Ok(_)`/`Some(_)`) over an env read, which cannot examine the value by construction — this leg exists because (a) could not see `match env::var("REDIS_URL") { Ok(_) => info!("Redis: configured"), … }`, two of which printed a green startup line for a subsystem that was off, in the very file that DEFINES the correct helper. Lines are joined into LOGICAL lines before matching (a continuation starting with `.`/`Ok`/`Some`/`Err`/`None`/`=>`/`{`), so the split `env::var("X")\n.is_ok()` form is caught — a line-based grep misses it, and that is precisely how this change's own first inventory came up short. Comment-only lines are dropped (the fixes' comments quote the banned expression verbatim; two would otherwise self-report). **Verified by running it against a clean `git archive` of `origin/main`: exactly 5 findings — `platform.rs` ×2, `metrics_server.rs`, `talos-config-validator` ×2 — and 0 on the fixed tree; 0 false positives.** **Stated limits, each measured rather than inferred:** it is TEXTUAL, so a presence test inside a helper in another crate or on a pre-resolved `Option<String>` is invisible; it deliberately does NOT flag a NAMED binding (`if let Ok(url) = env::var(..)`, `match env::var(..) { Ok(url) => … }`) — that shape was MEASURED against `git archive origin/main` at **56 non-test sites** (37 `let Ok(name) =` + 19 `match env::var`) of which **9 were genuinely defective**, i.e. 16% precision / an 84% false-positive rate, because nearly all of that population filters or parses the value on the very next line; linting it would be enforcement-shaped noise, so reviewers own that shape. All 9 are fixed in this same change and NONE is catchable by check 73: `talos-config-validator` ×4 (`validate_redis_tls` REDIS_URL — which warned "plaintext redis:// in production" for a Redis that was not configured at all; `print_summary` DATABASE_URL/BCRYPT_COST/JWT_SECRET), `talos-config::read_env_or_file` (the `<VAR>_FILE` PATH was unfiltered while the doc comment claimed both paths were), `talos-compilation::container_enabled` (the only BEHAVIOUR change in the sweep — `=""` forced containerised compilation ON in dev, inverting the unset default and fail-closing a dev box with no runtime), `talos-db::init_pool` (empty passed the "must be set" guard and failed later blaming TLS), `talos-hot-update-service::invalidate_redis_cache` (empty SKIPPED the "workers may serve stale WASM" warning), and `talos-worker-runtime::aot_key_ring` (`=""` produced a ZERO-LENGTH HMAC key in dev instead of the ephemeral-random fallback, and suppressed the warning saying so — while the controller's own `security_audit` correctly reported the key as missing, so the two disagreed); fail-CLOSED empty handling is NOT a defect and is out of range (a prod TLS gate that panics on `REDIS_URL=""`, a `KEK_PROVIDER=""` that refuses an unknown backend — "treat empty as unset" would WEAKEN those, so a future widening must not sweep them in); and it proves the empty case is HANDLED, never that it is handled correctly. The correct idiom now has one workspace-visible home, `talos_config::env_var_is_set_nonempty`, with the empty case pinned by `env_presence_empty_string_is_not_configured`. Opt-out `// allow-empty-env-presence: <reason>` on the reported line or within 8 lines above, for a genuine marker var where `FOO=` deliberately means "on".

  74. health-reporting handlers must not swallow a read into a benign default — `.await` followed by `.unwrap_or(0)` / `.unwrap_or_default()` / `.unwrap_or(None)` turns a DATABASE FAILURE into the most reassuring answer the surface can give: a count of 0, an empty list, a 0% error rate, a "not found". On a tool whose whole output is a statement about system state that lies in the one direction that matters — `handle_get_system_health` rendered `stale_executions: 0` and `unacknowledged_alerts: 0` from a Postgres blip, which is exactly what an operator opens it to check DURING an incident. **This class has now been repaired five times, each locally and each in a different vocabulary:** MCP-366 fail-closed the budget PRE-CHECK where a defaulted `0` was a security fail-open (2026-05-11) — and the identical `.unwrap_or(0)` on the identical repo method is still in `handle_get_actor_budget`, the tool that REPORTS the budget, so the path was fixed and the population was not; `handle_get_schedule_health` invented `data_warnings` (2026-05-06), #699 made `count_triggers_like` return `Result` so the caller could decline to say "run migrations", #702 added a per-check `verification: not_verified` to `security_audit`, and this change routes eight handlers through `talos_measurement::Readings`. **The scope is deliberately narrow and the narrowing is why it is shippable:** the bare shape occurs **179 times** across `talos-mcp-handlers/src` + `talos-api/src` and MOST ARE CORRECT — `is_platform_admin(uid).await.unwrap_or(false)` fails CLOSED and is right — so what separates the defect is not the DEFAULT but the SURFACE: inside a handler whose output IS a health verdict, every field is a claim about system state and there is no harmless default. Fires only inside functions named `system_health` / `health_dashboard` / `*_health` / `error_report` / `daily_digest` / `risk_assessment` / `readiness` / `system_status` — plus, from 2026-09-02, `budget` / `clone_actor` / `enqueue` / `plan_and_execute` / `workflow_triggers` / `module_rate_limit` / `suggest_retry`, and from #730 `module_info` / `validate_workflow_input` / `version_diff` / `archive_policy` / `secret_access`. **Measured against a clean `git archive origin/main`: 30 findings across 8 handlers, including all 6 in `handle_get_system_health`; 1 remains on the fixed tree and it is a true false positive carrying the opt-out (a graph read used only to resolve node UUIDs to display labels) — 96.7% precision, 3.3% FP.** Deliberately NOT a widening of check 52: that one is a `try_get(col)` COLUMN read inside repository crates whose fix is `?`-propagation and which is a graduated must-be-0 hard rule; this is a METHOD result in a report handler whose fix is disclosure, not propagation — merging them would blunt 52's regex and its zero-tolerance. The four together are one family: 34 (write-side format), 52 (read-side column), 55 (bare `.get` panic), 74 (report-side swallow). Stated limits: textual and name-based (a health surface named something else, or a default applied inside a service crate, is invisible); it does not judge the default's DIRECTION, which is the point inside these handlers but is also why it cannot be widened to the other 149 sites without precision collapsing; and it proves the error is not swallowed, never that the replacement is good. Opt-out `// allow-benign-default: <reason>` on the line or within 8 lines above, for a default that MAKES NO FAVOURABLE CLAIM — two shapes qualify and nothing else: a genuinely decorative read whose absence claims nothing about system state, and a fail-CLOSED default that costs the caller a refusal rather than granting anything (that second shape was added 2026-09-02 rather than stretching the word "decorative" over `is_platform_admin(..).unwrap_or(false)` silently — quietly reusing a marker for a second justification is the drift this file exists to catch). **2026-09-02 — the glob widening, and what it is NOT.** Six terms were added for the six handlers repaired that day, so this is a **REGRESSION GUARD for sites someone has already looked at, not a discovery mechanism for the next one**; a snapshot is not a gate (check 64), which is exactly why 74b exists and why the glob is not the answer to "how do we cover the surface nobody has examined". Measured in both directions before it was written: against the pre-fix tree the widened terms report **16 real sites** (3 in `handle_get_actor_budget`, 3 in `handle_clone_actor`, 5 in `handle_list_workflow_triggers`, 2 in `handle_enqueue_workflow`, 2 in `handle_plan_and_execute_workflow`, 1 in `handle_get_module_rate_limit`); against the fixed tree they report exactly **one**, the correct fail-CLOSED `is_platform_admin` in `handle_set_module_rate_limit`, now carrying the marker — so they ship at **ZERO** at 16/17 = 94.1% precision, comparable to the original glob's 96.7%. Note what the OLD glob reported on that same pre-fix tree: **one** line, and it was the already-opted-out one. That is why this class survived MCP-366 by four months in the handler MCP-366's own writeup names. **`.ok()` and `map_or` joined the default alternation in the same pass.** `.ok()` was found by MUTATION, not review: of seven mutations of that day's six fixes, six were caught and exactly ONE survived — `get_actor_budget`'s policy read reverted from a `match` to `.ok().flatten()`, i.e. the single highest-severity field in the set (the SPEND CEILING, rendered `null`, which reads as "unlimited"). Its measured population in scope was TWO, both genuine (the policy read, and `handle_get_all_readiness_scores`'s population aggregate, which disclosed its failure in `summary.population` prose while the `Readings` ledger beside it stayed clean and therefore rendered "complete: every field in this report was measured" — two disclosures in one response contradicting each other); both fixed, so it ships at zero with no marker. `map_or` closes evasion E5 and its population in scope is ZERO on both trees. **The alternation is NOT a closed set and must not be read as one:** three evasions were measured as SURVIVORS and are left open deliberately — `match { Err(_) => <default> }` (a block, not a chain, and the shape TWO of the three original SLA defects took), a default applied to an already-resolved local one statement later, and handling routed through a helper in another crate. What the check buys is that the ORDINARY spelling cannot come back silently. **The nested-`fn` hole was closed in the same pass, and it is the sharpest self-indictment here:** function attribution rebound on ANY `fn` header, so an inline helper stole the enclosing handler's name for everything below it — `handle_get_actor_budget` defines two `opt_or_unlimited_*` helpers mid-body, and the LLM-TOKEN-LEDGER read beneath them was filed under `opt_or_unlimited_i64` and filtered out by the glob, i.e. the most security-adjacent number in the handler was invisible BY CONSTRUCTION and no amount of glob widening would have reached it. Rebinding is now gated on indentation (same level or shallower) with a column-0 `}` resetting the tracker, so an inline helper leaves the handler's name in place while a method inside an `impl` still starts a new function; probe-proven in three directions (read-below-helper fires under the handler; a non-reporting `impl` sibling does not inherit the health handler above it; a `*_readiness` sibling is seen under its own name). Both legs carry the rule, and it is why the pre-fix count is 5 in `handle_get_actor_budget` rather than 4. **Sub-leg 74b (2026-09-02, no new number — `--count` stays 74): a `Readings` ledger must cover every awaited read in its function.** Leg 74's function filter is a HAND-MAINTAINED NAME GLOB, the rot mode #624 and check 64 already cost this repo. It was MEASURED against the pre-fix tree of the SLA compliance bug — a workflow with zero executions reporting `in_compliance: true`, `success_rate.actual: 100.0`, `met: true` beside `total_executions: 0`, verified live in two states — and the measurement settles the shape of the guard rather than the shape of the patch: **adding `sla` to the glob makes leg 74 fire on `handle_get_workflow_sla_report` at exactly ONE line, the ownership lookup's `.await`/`.unwrap_or(None)`, and on NONE of the three defects the bug was about** (`else { 100.0 }`; `p99.unwrap_or(0.0) <= target`, true FROM ABSENCE while the same response emits `p99: null`; and a `match { Err => 0 }` violations count that rendered a DB error as *zero violations*). Two of those three carry no `.await` in the expression at all and the third is a match block, so none was ever in leg 74's range. Widening the glob would have turned the check RED on the right handler for the wrong line and GREEN once that line was fixed — a green tick standing over all three real defects, the gate-that-doesn't-gate class one level up. The glob was therefore deliberately NOT widened. 74b's scope is instead **DERIVED from the code**: any function constructing a `talos_measurement::Readings`. A handler opts itself in by adopting the pattern, so a new report surface is covered the moment it adopts one and no name list can rot. Inside that scope the claim is STRONGER than leg 74's: `Readings::note()` renders "complete: every field in this report was measured" and `attach` adds nothing when the ledger is clean, so a defaulted read beside a clean ledger is not a missing disclosure but an affirmative FALSE COMPLETENESS claim — the disclosure lying about itself. Measured population on this tree: TWO, both the same `.await`/`.unwrap_or(None)` ownership-or-label shape (the SLA handler's, fixed here; `handle_get_error_report`'s, which already carried the `allow-benign-default` marker for being label prettification) — so it ships at ZERO, not as a ratchet. **Stated limits, each proven by mutation rather than inferred:** (a) it only sees functions that ALREADY adopted `Readings`, so it COMPLEMENTS the glob and does not replace it — a surface that never adopted the pattern is invisible; (b) it inherits leg 74's regex — **which it did NOT until #730**: this very sentence shipped saying "exactly" next to code matching `.unwrap_or*` alone, hours after leg 74 gained `ok|map_or`, with the next clause of the same sentence then listing `.ok()` as invisible; the header contradicted itself and the reassuring half came first. `.ok()` is also the spelling #727 found only by mutation. Widening it cost ZERO new sites on either tree. A `match { Err(_) => <default> }` block and an `unwrap_or` on an already-resolved local remain invisible, and **it therefore would NOT have caught any of the three original SLA mechanisms** — run against the original tree it reports 0. What it DOES catch is the regression shape (a call-site `.await`/`.unwrap_or(0)`), which is precisely what the renderer's unit tests provably CANNOT see: mutating the call site left all seven `sla_absence_disclosure_tests` green, and 74b fails on it. That division of labour is the design — the pure renderer is guarded by tests (which catch the two verdict mutations), the wiring by 74b (which catches the third) — and neither instrument alone covers the bug. `Readings::default()` is matched alongside `Readings::new()` so the obvious evasion does not work. **#740 widened it a second time, with the `if let` spelling** — `if let Ok(Some(x)) = <read>.await` is the same collapse in a shape the chain alternation structurally CANNOT see: there is no `.unwrap_or`, no `.ok()`, no `map_or`, the discard IS the `if`. Not theoretical — `handle_get_workflow_health` built a `Readings`, wrote `sub_workflows: []` from a swallowed graph read, and 74b reported **zero** on it while the ledger published "complete: every field in this report was measured". Measured on pristine `origin/main` before widening: the workspace holds exactly TWO occurrences of the spelling, one of which is that defect and the other of which is in a repository crate with no ledger — so the leg contributes **1 finding, 1 real, 0 false positives**, and 0 on the fixed tree. Whole-line comments are dropped first (check 73's lesson: the fix's own comment quotes the banned expression). The same change also found that the two swallows INSIDE that function's `tokio::join!` (`names_res.unwrap_or_default()`, `stats_res.unwrap_or_default()`) are invisible to BOTH legs, because the `.await` lives in the `join!` and not in the defaulted chain — a real, open, stated limit, not a hypothetical one; (c) like leg 74(c) it proves the read is not swallowed, never that the handling is good. **#730 — the third glob group, and what the measurement says about the glob itself.** Five terms (`module_info` / `validate_workflow_input` / `version_diff` / `archive_policy` / `secret_access`) for five CONFIGURATION-claim surfaces, on the second group's footing: a regression guard for handlers someone has now looked at, not a discovery mechanism. Measured both ways: **11 sites on the pre-fix tree, 9 of them real** (`handle_get_module_info` ×2, `handle_test_secret_access` ×3, `handle_get_version_diff_summary` ×2, `handle_validate_workflow_input`, `handle_get_archive_policy`) and 2 the correct fail-CLOSED `is_platform_admin(..).unwrap_or(false)` now carrying the marker; **0 on the fixed tree**. 81.8% precision — below the second group's 94.1%, and stated rather than rounded up, because both FPs are the shape the opt-out's second clause exists for. **The OLD glob reported 0 of those 9.** Not one of the five tools is named "health": they answer *which secrets does this module grant*, *is this payload acceptable*, *what changed since publish*, *where does the archive policy come from*. So the glob's blind spot is VOCABULARY, not depth — and the tools it missed were making claims an operator acts on directly. `validate_workflow_input` is the one to remember: it returned `unvalidated: true` beside its own advice to *"gate on `unvalidated === true` to accept schema-less input intentionally"* for a workflow that **did not exist**, live, with no DB outage in play — the repository method flattened "no such workflow" into "no schema declared", so a mistyped id became a recommendation to accept the payload. And `get_archive_policy` is the class's signature: MCP-552 fixed this defect byte-for-byte in the sibling `handle_get_wasm_config` ("would proclaim `source: 'env defaults only'` even when the DB was unreachable") in **May 2026**, one file away, and nothing swept it — the sixth local repair of a class with no population sweep behind it.

  76. an input-schema read must be CLASSIFIED, not defaulted — `workflows.input_schema` decides whether the input-validation gate runs at all, so a read of it that does not come back with a definite answer must REFUSE, never fall into the same branch as *"this workflow declares no schema"*. **A gate that silently does not run is indistinguishable, in every response and every log, from a gate that passed.** Three sites had the defect and each spelled it differently, which is why this is a check and not a review note. `WorkflowValidationService::check_trigger_input` degraded a fetch `Err` to `None` and **said so in its own doc comment**, justifying it as availability (*"rather than rejecting all triggers on a transient DB hiccup"*) — a justification refuted by its own single caller, where the three repository reads and the authorization resolve ABOVE it (`is_execution_paused`, `get_workflow`, `get_active_version_graph`, `resolve_effective_actor`) every one returns `Err` on a DB failure: on a transient hiccup the trigger was already dead three reads earlier, so the availability that arm claimed to buy had been spent above it, and the window it actually covered was a failure specific to that ONE query, in which the only thing it bought was dispatching input nobody checked. `handle_call_workflow` and `handle_test_workflow` wrote `if let Ok(Some(schema)) = …`, which routes BOTH the read error and the unknown-workflow answer into the silent skip branch — under comments claiming the gate exists so *"a sync-call doesn't bypass the gate"* and so *"a green test is [not] silently less strict than a real trigger"*, i.e. both parity claims held only while the database was answering. Two legs, because either alone is trivially evaded: **(a)** the FLATTENING projection `get_workflow_input_schema` may be called only inside `talos-workflow-repository/` — its own doc comment says it collapses "no such workflow" into "no schema", so every outside caller inherits that flattening whatever it then does; outside callers take the three-way `_scoped` sibling (#730); **(b)** a `_scoped` call outside the repository crate must have a classifier named within the 6 lines above it (`classify_input_schema_read` / `decide_trigger_input` / `enforce_declared_input_schema`) — without (b), (a) is defeated in ONE line by `get_workflow_input_schema_scoped(..).await.ok().flatten().flatten()`, which reproduces the original defect exactly, and leg (b) was CONFIRMED by mutation to fire on it; **(c)** the three DECISION functions must not be called into a `let _ =`. Leg (c) exists because legs (a) and (b) both live at the READ and neither can see a call site that runs the gate correctly and then throws the answer away: `let _ = decide_input_schema_outcome(validation, wf);` was MEASURED as a survivor of every other instrument here — all 31 crate tests green, legs (a) and (b) green, and check 10 green because it is scoped to `talos-mcp-handlers/src` — which is #724's shape exactly (a call-site mutation that left every test green). The BARE-statement discard needs no lint: all three functions now carry `#[must_use]`, so CI's `-D warnings` refuses it (verified — clippy reports *"unused return value of `decide_input_schema_outcome` that must be used"*), and `let _ =` is the documented way to silence `#[must_use]`, so it is the one spelling a lint has to cover. **Measured before it was written, in both directions: 3 findings on the pre-fix tree — exactly the three defects, 0 false positives — and 0 after.** A FILE-scoped formulation ("the file must name a classifier") was built FIRST and REJECTED on measurement: all three MCP sites live in one file that already named `classify_input_schema_read` from #730's reporting fix, so it reported **0 on a tree containing 2 of the 3 defects** — the gate-that-doesn't-gate class (#624, checks 64/65) reproduced inside the guard for it. Scope is DERIVED from the method name, not a hand-maintained handler glob (check 74's rot mode), so a brand-new enforcement site in a crate nobody has thought about is covered the day it is written — probe-confirmed against a fresh call added to `talos-scheduler`. **Stated limits, each confirmed by mutation rather than inferred:** both legs are TEXTUAL and line-based, so a read reached through a wrapper in another crate or renamed by a re-export alias is invisible to both; (b) is WINDOW-bounded at 6 lines and the three live sites pass the read straight into the classifier with no intervening binding (measured max distance 3 lines), so a reflow that pushes the classifier further up reads as unclassified — a FALSE POSITIVE, the loud direction; (b) proves a classifier is NEARBY, never that its answer is honoured — the **measured survivor** is a classifier that runs and is then overridden one statement later (`let lookup = match lookup { Unreadable(_) => NoSchema, other => other };`), which reproduces the defect in full while all three legs stay green; that is the same already-resolved-local shape check 74 lists as an open evasion, and closing it needs dataflow, not a grep, which is why the refusal behaviour itself is pinned by unit tests driving the production decision functions (`trigger_input_failclosed_tests`, `trigger_input_gate_tests`, `input_schema_enforcement_tests`); and neither leg says anything about the OTHER fail-open enforcement gates in this workspace (capability ceilings, module rate limits, Rhai policy evaluation, the dispatcher signing-key gate) — that population is real and larger, but a wider regex would be enforcement-shaped noise. `<crate>/tests/` binaries are excluded; a `#[cfg(test)]` module inside `src/` is NOT. Opt-outs `// allow-flattened-schema-read: <reason>` (a) and `// allow-unclassified-schema-read: <reason>` (b), on the reported line or within 8 lines above.

  77. `__error` must be CLASSIFIED, not shape-assumed — `__error` is one of exactly TWO `__`-prefixed keys that survive the reserved-key strip on a module's own output (`engine_dispatch_system.rs` retains `__error` and `__continued` deliberately), and `collapse_subworkflow_output` returns a single terminal node's output **VERBATIM**. So the value a reader sees can have been authored by a WASM module, by a custom `NodeDispatcher` (which `docs/workflow-engine/custom-dispatcher.md` explicitly tells integrators to use for an error envelope), or by an LLM — none of it validated. `.get("__error").and_then(|v| v.as_bool()).unwrap_or(false)` returns `false` for ANY non-boolean value, so a module reporting `{"__error": "upstream 502"}` read as a **clean run**. **Twelve sites shared the shape**, and the benign collapse decided: execution status (`route_system_node_output` — a `sub_workflow` node whose child's terminal module reported a string error was committed as SUCCESS and the workflow marked `completed`), `node_completed` vs `node_failed` in the events table, ensemble consensus winner selection (`first_pass` would pick a FAILED candidate), reflective-retry's quality gate, loop termination reason (the loop body IS a module, so this one is directly module-authored — and its own comment says it exists so "the termination reason reflects reality instead of silently rolling up 'looks like we ran N iterations'"), and the `test_subworkflow_contract` verdict. The rule now has ONE home — `talos_workflow_engine_core::reserved_keys::classify_error_flag` / `output_reports_error`: **only absent / `null` / `false` / `""` mean success; every other value is a failure.** That is not a new rule, it is the one `talos-engine`'s Rhai condition scope (`build_condition_scope`) had always used for `is_error`/`error_message` — the two readers DISAGREED about the same output, and the Rhai one was right. Note a bare `.is_some()` is the OPPOSITE error: `{"error": null}` is the success envelope `database-query`-style templates emit, so presence is not the test. **A behavioural test cannot cover this population, which is why it is a lint:** reverting the single highest-severity site (execution status) left all **244** engine unit tests green. **Measured in both directions: 12 findings on the pre-fix tree, 0 after.** Stated limits: TEXTUAL and window-bounded (4 lines from the read, whole-line `//` comments dropped so a doc/test comment quoting the banned expression does not self-report — check 73 was bitten by exactly that); lines are joined before matching, so an `.as_bool()` and an unrelated `.unwrap_or` within 4 lines is a false positive (loud direction); it pins the `.unwrap_or` spelling only, so `as_bool() == Some(true)` and `matches!(…, Some(true))` are invisible — measured at **0** today, and the 9 remaining `.as_bool()` reads are all `assert_eq!(…, Some(true))` test assertions on ENGINE-authored values, which are precise Option comparisons and correctly out of range; and it says nothing about the other reserved keys, deliberately — `__continued` is the only other module-reachable one and has NO shape-coercing reader (checked), while `__skipped`/`__judge_*` are stripped from module output. Opt-out `// allow-unclassified-error-flag: <reason>`.

  78. ONE production signing gate for NATS dispatch — `ensure_signing_key_present_in_production` refuses to dispatch when `WORKER_SHARED_KEY` is unset in production (unsigned `JobRequest`s are forgeable and replayable on the wire). **Its own docstring claimed it was "extracted … and applied to ALL public NATS-dispatch entry points". It was applied to THREE of four.** `build_nats_dispatcher` is the fourth: it returned a dispatcher rather than running one, so a caller that builds a dispatcher and drives it itself — `execute_subworkflow_graph`, i.e. the `test_subworkflow_contract` tool — bypassed the gate entirely while its three siblings refused. **And the false claim was DOUBLE:** `talos_mcp_handlers::utils::load_worker_shared_key_logged`'s docstring asserted the same property from the other side ("the hard fail-closed in production happens downstream — *every* NATS dispatch path runs through `run_with_trigger_input_via_nats`") and was false for that same one path, so two comments in two crates propped each other up. This is #732's class (a comment asserting a safety property the code drops) one file over. The fix is structural, not a fourth call site: the gate now lives at the **dispatcher-construction chokepoint**, has exactly ONE caller, and returns `Result`, so a fifth entry point cannot be added without handling the refusal — the type system enforces what the comments used to claim. Two legs: **(a)** `build_nats_dispatcher` must still return `Result` AND still call the gate (a refactor could keep the signature and drop the call, or vice versa) — on the pre-fix tree this leg fires on BOTH counts, so it is measured against the real defect rather than a synthetic one; **(b)** a raw `NatsNodeDispatcher::new(` may be constructed only in `talos-engine/src/nats_run.rs` and inside `talos-workflow-engine-nats/` (the type's own crate + its tests), because without it (a) is defeated by hand-rolling a dispatcher beside the builder. **Leg (b) ships at ZERO and is PROPHYLACTIC — it found nothing on either tree**, and saying so matters more than implying it caught something. Also fails LOUDLY if `nats_run.rs` or the function is renamed away, rather than skipping (a check that skips is not a gate — checks 64/65). Stated limits, both legs TEXTUAL: (a) finds the function by name and reads to the next column-0 `}`, so a rename or a column-0 brace inside a string misleads it (loud direction — the region shrinks and the gate reads as missing); (b) pins one constructor identifier, so a differently-named dispatcher type, or one obtained from a helper in a third crate, is invisible; neither leg can prove the gate's DECISION is right, only that it is present and able to refuse. Severity note for the record: on the dev deployment the gap is LATENT twice over (`RUST_ENV` unset so `is_production()` is false, and `WORKER_SHARED_KEY` is set anyway), and with `TALOS_DISPATCH_SCHEME=ed25519` a missing WSK would not literally produce unsigned jobs — the gate is a conservative fail-closed refusal on the HMAC path. The defect is the ASYMMETRY: three of four entry points refused and one did not. Opt-out `// allow-ungated-nats-dispatcher: <reason>` (leg b).

  79. an integration read must be CLASSIFIED, not collapsed into "not found" — `service.get_integration(user, id)` returns `Result<Option<_>>` and the two failure shapes mean opposite things: `Ok(None)` is *that integration does not exist* (404 correct), `Err` is a pool timeout / Postgres restart / projection drift (*we could not look*). **Four handlers wrote `Ok(Some(i)) => i, _ => 404 "Integration not found"`**, so a DATABASE FAILURE told the operator their integration DOES NOT EXIST — the most reassuring answer the surface can give, and false. **The correct form was already one file away in the same crate**: gcal's `test_watch_channel_handler` splits `Ok(None)` (404) from `Err(e)` (log the full chain server-side, return a generic 500), and every one of the four collapsed sites sat directly ABOVE a `get_access_token` arm that handled `Err` correctly — so this is not a rule nobody knew, it is a rule that did not replicate when `docs/integration-pattern.md` was copied for the second and third integration, which is what the fourth will do too. Detection: a bare `_ =>` / `Err(_) =>` arm within 3 lines of an `Ok(Some(` arm whose scrutinee (within 12 lines above) calls `.get_integration*(`. Scope is DERIVED from the method name, not a hand-maintained crate list (check 74's rot mode) — a fifth integration crate is covered the day it is written. **Measured in both directions before it shipped: 4 findings on a clean `git archive origin/main` (gmail ×2, gcal admin, google-cloud) — exactly the four real defects, 0 false positives — and 0 on the fixed tree**; it does NOT fire on the correct `Ok(None)` + `Err(e)` sibling. **Stated limits, each confirmed rather than inferred:** TEXTUAL and line-based, so `if let Ok(Some(x)) = svc.get_integration(..)` collapses identically and is invisible — measured at **0** occurrences today, so the leg ships covering the shape that actually exists; WINDOW-bounded (12 lines scrutinee→arm, 3 arm→wildcard), so a reflowed match reads as clean — a false NEGATIVE, the quiet direction; it matches on the METHOD NAME, so the same collapse over a differently-named read is out of range; and it proves the arms are SPLIT, never that the `Err` arm is right — **measured, not inferred**: splitting `Ok(Some)`/`Ok(None)`/`Err(e)` correctly and then having the `Err(e)` arm return the 404 with the original `"Watch not found"` text SURVIVES this check, and the direction is UNDER-reporting (green while the handler still tells the caller their watch does not exist). **Leg (b) — the callee contract, #740.** The first version of this check recorded, as a stated limit, that `find_by_id` / `find_channel_by_id_raw` "cannot be split at the call site at all": they returned `Result<Row>` with ABSENCE ALREADY FOLDED INTO `Err` by `talos_integration_helpers::state_store::get_entry`, whose `.map_err(|e| anyhow!("integration_state get failed: {:?}", e))?` turned `execute_op`'s `Err(KeyNotFound)` — its ANSWER for "no such row" — into a string. `Ok(None)` was structurally unreachable and its own doc comment said so. `get_entry` is now genuinely three-way (`Ok(Some)` / `Ok(None)` / `Err`) and the three readers return `Result<Option<Row>>`, so leg (b) covers them. The pre-split shape is a plain `Ok(r) => r`, NOT `Ok(Some(`, so leg (b) anchors on the wider `Ok(`. **Measured in both directions: SEVEN findings on a clean `git archive origin/main`, all seven real, 0 false positives** — the three probe handlers (`Err(_) => 404 "Watch not found"`), the three `stop_watch` / `stop_watch_channel` idempotency arms (`Err(_) => return Ok(())`, i.e. a pool timeout reported as a SUCCESSFUL stop of a watch that is still running and still pushing), and gmail's push-loop row re-read (`Err(_) => row.clone()`, an undisclosed fall back to a stale row) — **and 0 on the fixed tree**, with both call sites mutated back correctly reported. Widening leg (a) to the same `Ok(` anchor was measured and changes nothing on either tree, so leg (a) is left narrow. Opt-out `// allow-collapsed-integration-read: <reason>` on the read line or within the 8 lines above.

  **Sub-leg 79b (#740, no new number — `--count` stays 79): a WORKFLOW-GRAPH read must be classified, not collapsed.** Same rule, second method family, scope derived from the method name rather than a crate list. `workflows.graph_json` is `TEXT NOT NULL` and every reader queries `WHERE id = $1 AND user_id = $2` through `fetch_optional`, so the three outcomes are unambiguous and mean three different things — and four sites routed `Err` into one of the other two. The severity is not uniform and the spread is the point: `handle_validate_workflow`'s `_ => "{\"nodes\":[],\"edges\":[]}"` did not merely lower a score, it computed EIGHT fields over a graph nobody read (`node_count: 0` / `edge_count: 0` for a workflow that has nodes) and then told the operator to add node descriptions, an execution timeout and error edges **that are already there** — specific, actionable, wrong advice; `handle_list_workflow_webhooks` and `HandoffService::execute` answered "Workflow not found or access denied" on a DB failure (#736's shape verbatim, and the handoff one sits on an AUTHORIZATION path, so the refusal direction was right and only the DIAGNOSIS was wrong — which sends an operator to look at permissions during a database incident). **Two shapes are deliberately out of range, by one test — does the substitute make a STATEMENT to a caller?** `.ok().flatten()` feeding `build_node_label_map` (twelve sites in `executions.rs`; the fallback prints the bare node UUID, the counts beside it are untouched) and a VALUE-FREE `_ => return` in a `-> ()` helper (it abandons background work; nobody is waiting). **Measured in both directions before it was written, against a clean `git archive` of `origin/main`: FIVE findings, one carrying the opt-out, so four reportable — exactly the four defects, zero false positives — and 0 on the fixed tree.** Stated limits, each confirmed rather than inferred: TEXTUAL and WINDOW-bounded at 8 lines, so a reflowed match or a read reached through a wrapper in another crate is invisible (false NEGATIVE, the quiet direction); it matches the METHOD-NAME family, so the same collapse over a differently-named graph read is out of range; the value-free-`return` exclusion is literal, so `_ => return None` in a `-> Option<T>` helper still fires (loud, and correct — `None` IS an answer); and it proves the arms are SPLIT, never that the `Err` arm is right. **Three call-site mutations initially SURVIVED it and every unit test, all three in the UNDER-reporting — silent — direction, and two are now CLOSED.** Closing them required what the lint structurally cannot do: `handle_validate_workflow`'s 460-line body was extracted into the pure `render_validate_workflow(wf_id, GraphRead, ValidationResult, ReadinessReads) -> ValidateWorkflowOutcome` (no `async`, no repository, no `McpState`, and the CLOCK passed in so `freshness` is testable), leaving a 78-line handler that only reads — the Architectural Mandate's own direction, and #730's `render_input_validation` shape in the same file. Re-measured after the extraction: **M5** (drop the `degraded_inputs.push("graph")`) now FAILS `an_unreadable_graph_makes_no_claim_about_the_workflow`; **M6** (re-emit `node_count` unconditionally — which fully restores the original defect) FAILS the same test; and so does **M8** (withdraw any one of the three graph-derived recommendation guards), which was not previously covered at all. **M7** — rendering `get_workflow_health`'s `sub_workflows` as `[]` rather than `null` — STILL SURVIVES, deliberately: that list is built by a loop interleaving three reads, so extracting it means restructuring the loop, and unlike the validate case its failure is already self-evident in the response (the `Readings` ledger names `sub_workflows` under `not_measured`, so the mutation makes the response CONTRADICT ITSELF rather than lie cleanly). Note what the extraction proves in general: a guard at the READ cannot see the CONSEQUENCES of a read being mis-rendered 300 lines later — only a pure renderer with the whole consequence set in one function can, which is the argument for the thin-handler rule restated as a measurement. Opt-out `// allow-collapsed-graph-read: <reason>` on the read line or within the 8 lines above — and note the one exempted site (`handle_get_error_report`'s label read) carries its OWN marker rather than borrowing check 74's `allow-benign-default`, because a marker quietly serving a second justification is the drift these checks exist to catch.

  80. every Postgres image reference must be the SAME pinned digest — the version was named in SEVEN places and had silently split three ways: `docker-compose.yml` (postgres, postgres-backup, vault-backup) and `.github/workflows/ci.yml` pinned **pg16**; `quality.yml` ran an **UNPINNED pg17**; `controller/tests/test_helpers` used a testcontainers tag; `scripts/drills/backup-restore.sh` pinned pg16 — while PRODUCTION (`deploy/helm/talos/values.yaml`: "derived from `postgres:17`") is **pg17** and `migrations/.baseline/schema.sql` is dumped from **17.10**. **Not cosmetic.** That baseline emits `SET transaction_timeout = 0`, a PG17-only GUC, so on pg16 `migrate_db()` fails under `ON_ERROR_STOP=1` and `make test-integration` is unrunnable locally — **while the job that VERIFIES the baseline runs on the one version where it works**, so the gate stayed green over an artefact that could not be applied in the environment developers use (the gate-that-doesn't-gate class, checks 64/65, at the infrastructure layer). Two sites were correctness bugs outright: `pg_dump` REFUSES to dump a server newer than itself (`postgres-backup` would have silently stopped backing up), and a scratch server cannot restore a dump from a newer major (`backup-restore.sh`, whose whole purpose is proving a restore works). A shared config mechanism is impossible — the sites are compose YAML, Actions YAML, Rust and bash with no common substitution — so this lint is the enforcement that duplication needs, exactly as check 62 is for the three `build.rs` copies and check 16 for the duplicated WIT file. **Precision is trivially 100%**: an exact-match assertion over a literal, not a heuristic. Three directions fail it: a DIFFERENT digest, an UNPINNED `pgvector/pgvector:pgNN` tag (an upstream rebuild would silently change what runs), and a testcontainers `.with_tag("pgNN")` disagreeing with the pinned tag. The canonical pin is read from `docker-compose.yml`, so bumping the version is a one-line edit there plus the sites this check then names. Stated limit: it verifies the references AGREE, never that the pinned version is the RIGHT one — that is what `deploy/helm/talos/values.yaml` and the baseline's own `Dumped from database version` header say, and neither is machine-checked against it. Opt-out `# allow-postgres-image-drift: <reason>` on the referencing line.
  81. ARCHIVED is not ABSENT on a by-id execution read — `ExecutionRepository::get_execution(exec_id, user_id) -> Result<Option<_>>` read `workflow_executions` ALONE, so `Ok(None)` meant *no such execution* and *the retention sweep moved it to `workflow_executions_archive`* indistinguishably, at every one of its twenty-two call sites. **That was academic until #746**: the archive had held ZERO rows across the platform's entire history, so no reader had ever had to represent an archived execution. #746's first boot pass moved 96 real executions in, and within the hour four tools answered `"Execution not found or access denied"` about one of them — a sentence whose BOTH clauses are false: it IS found (`list_archived_executions` returns it) and access is NOT denied (same user, same tenancy predicate). The misleading-report class (74, 76, 79/79b) once more: a determinate negative asserted for a state the reader cannot represent. The fix is structural — `lookup_execution` returns `ExecutionLookup::{Live, Archived{row, archived_at}, Absent}`, `#[must_use]`, with no `Into<Option>`, no `row()` accessor and no `.ok()`, so the compiler enforces most of the rule. Three legs cover what it cannot. **(a)** the deleted flattening reader must stay deleted (`pub async fn get_execution(` may not be defined in `talos-execution-repository/src/`) — check 68(c)'s shape; measured 1 on pristine main, 0 after, precision trivially 100% since it is an exact assertion over a definition site. **(b)** no call site may fold the two back together — a `.get_execution(` whose `Ok(None)`/`None` arm renders a not-found answer. **This is the leg measured against the REAL defect rather than a mutation: against a clean `git archive origin/main` it reports FOURTEEN sites** (the thirteen `talos-mcp-handlers/src/executions.rs` handlers plus `talos-failure-analysis-service::analyze`), **every one a real instance, 0 false positives, and 0 on the fixed tree** — `talos-api`'s `module_execution_logs` calls `ModuleExecutionService::get_execution` over a different table with no archive tier, but spells its check `.is_none()` rather than a match arm, so it is out of range by shape. **(c)** an `Archived` arm may not render the not-found string, and a `lookup_execution` match may not carry a `_ =>`/`Ok(_) =>` wildcard (which swallows `Archived` past the exhaustiveness check). **Leg (c) ships at ZERO and is PROPHYLACTIC — it found nothing on either tree**, and saying so matters more than implying it caught something; both halves are mutation-proved by reinstating the collapse at `handle_get_execution_status` in either spelling. **Stated limits, each confirmed rather than inferred:** all three legs are TEXTUAL — (a) pins one identifier in one crate, so a differently-named flattening convenience (`fetch_execution`) is invisible, the same limit 68(c) states; **(b) is WINDOW-bounded at 600 chars and does NOT see the `.ok_or(OrchestrationError::ExecutionNotFound(..))?` spelling**, which is exactly how `talos-execution-orchestration`'s `retry` and `replay` wrote it — those two ARE real pre-fix defects and leg (b) reports neither, so main's true population of the class is 16 and the leg sees 14 (measured, not assumed); (c)'s arm-body window stops at the next arm of the same match, and without that stop the sibling `Absent` arm — which legitimately renders the not-found string — lands in the window and **every site false-positives, measured at 14 of 14** before the stop was added; and no leg can prove the `Archived` arm's answer is GOOD, only that it is distinct — a handler that classifies correctly and then renders a bare "archived" with no timestamp passes all three, which is why the wording is pinned by `archived_render_tests` instead. Companion migration `20260904210000_rls_workflow_executions_archive.sql`: the archive had `relrowsecurity=false` and ZERO policies while holding real tenant ciphertext, so the app-layer `AND user_id = $2` was its only tenancy guard — the policy is copied clause-for-clause from `20260529200000` and proved by `execution_archive_read_tests`. Opt-out `// allow-collapsed-execution-read: <reason>` on the reported line or within the 8 lines above.
  82. an engine write-ceiling gate must NOTIFY the refusal recorder — the gate and the instruments that say it fired live in different crates, and one deleted call separates them. `apply_memory_write_ceiling` (`talos-workflow-engine`) removes the refused `__memory_write__` envelope and RETURNS the refusal; it records nothing and cannot — the engine has no metrics registry, no database, no audit target of its own. The single recorder is `ControllerNodeHook::record_memory_write_refusal` (`talos-engine`), which the engine reaches ONLY through `NodeLifecycleHook::on_memory_write_refused`. Delete that one call and the gate still gates perfectly while every instrument goes permanently silent: no `talos_audit` WARN, no `talos_memory_write_failures_total{reason="write_ceiling"}` — a refusal indistinguishable from a write that never happened, which is the exact reading the gate exists to remove. **Check 58 cannot see this**: it proves an `.inc()` SITE EXISTS and says nothing about whether anything reaches it, which is its own stated wrapper limit ("gutting a wrapper body is caught, deleting all its call sites is not") in its sharpest form — here the wrapper is in another crate and the call site is the only bridge. Population is 2 (`engine_completion.rs`, `engine_dispatch_pipeline.rs`); it ships at **ZERO** and is mutation-proved in both directions (renaming either `hook.on_memory_write_refused(…)` reports that file; the node-completion one also turns `controller/tests/write_ceiling_memory_write_tests` red with `left: 0.0, right: 1.0`). **It is not redundant with that test**, and the reason is the point: the test covers the NODE-COMPLETION site end to end (counter delta, audit target, `op`/`policy`/`ceiling`/`key`/`actor_id`/`node_id`) and cannot cheaply reach the PIPELINE-STEP site — chain dispatch is `ChainDispatch::Disabled` on every production entry point, and the in-crate unit-test route is blocked by `controller_write_ceiling_enforced()` being a process-global `OnceLock` that sibling tests race. This check is that site's only guard. Fails LOUDLY (not skip) if `write_ceiling_gate.rs` is gone or if it matches no caller at all — a check that matches nothing is a green tick over zero statements (checks 64/65). **Stated limits, each confirmed by mutation rather than inferred:** TEXTUAL, so a notification routed through a helper in a third crate is invisible; it matches `on_memory_write_refused(` WITH the paren so ordinary prose cannot vouch for a deleted call, but a commented-OUT call still can; it fires on the FILE, not the call, so a file with two gate sites and one notification passes; and it proves the notification is PRESENT, never that it sits inside the refusal branch, that a hook is wired at all, or that the recorder does anything once reached (the metric pre-seed and the audit vocabulary are pinned by `alerted_counter_vecs_are_seeded_at_zero_on_a_cold_registry` and the controller test respectively). Opt-out `// allow-ungated-refusal-notify: <reason>` anywhere in the file.

  83. an explicit `updated_at = NOW()` must not override the trigger's verdict — `workflows.updated_at` is the platform's "last modified" claim (ten `ORDER BY updated_at DESC` readers, the GraphQL `Workflow` type, several MCP handlers), and it was a MAINTENANCE CLOCK: the generic `update_updated_at_column()` trigger stamped the row on ANY column change, so the hourly readiness recompute in `controller/src/bootstrap/background.rs` overwrote it fleet-wide. Measured 2026-09-05: **all 36 workflows had `updated_at = readiness_computed_at` to the microsecond**, and 75 of 112 `modules` rows shared one boot second. The true edit history is unrecoverable, and the damage is not only cosmetic — `resolve_by_capabilities` picks the workflow to EXECUTE with `ORDER BY updated_at DESC LIMIT 1` and `run_workflow_chains` picks which chained workflows fire, so with every row tied inside one second both were resolving on HEAP ORDER. Migration `20260905120000` makes the trigger self-describing: each trigger declares its table's MAINTENANCE columns as `TG_ARGV` and the shared function bumps only when something outside that set changed. A deny-list, not an allow-list, deliberately: a column added later is CONTENT by default, so a new user-editable column stays honest with no action, and the residual duty falls on whoever adds a DERIVED column — the person writing the maintenance job, i.e. the one already thinking about it. **The trigger alone does not close it, which is what this check is for.** The trigger can decide whether to OVERWRITE `updated_at`, never to REVERT one, so a statement writing `updated_at = NOW()` itself is exempt from the verdict — and the catalog seeder is exactly that: an `ON CONFLICT … DO UPDATE SET …, updated_at = NOW()` re-issued for every catalog row at every boot. **The first DB test for this was green over the live defect** because it exercised a plain `UPDATE modules SET description=…, source_code=…`, a shape the seeder does not issue; `an_explicit_stamp_overrides_the_trigger` now pins the real one. **Measured in both directions against a pristine `git show HEAD:` copy: 7 findings, all 7 real, and 0 after** — six of them catalog upserts spanning BOTH source-of-truth modes (disk seeding AND the OCI registry sync in `talos-registry/src/sync.rs`), so patching one mode would have left the other. **Stated limits, each confirmed rather than inferred:** the detector deliberately does NOT parse Rust string literals — an earlier literal-parsing inventory written for this same change missed `sync.rs` entirely, and on the sibling ORDER BY sweep missed two more sites, because one desynchronising quote earlier in the file put the statement outside what the parser considered a literal; scanning for the SQL keyword sequence has no such failure mode, at the cost of being TEXTUAL and WINDOW-bounded (8000 chars from `INSERT INTO`, truncated at the first `.bind(`/`.execute(`/`.fetch_*(`), so `format!()`-assembled SQL or a statement split across two literals is invisible — the quiet direction. The eight-table list is HARDCODED and must grow when a table starts carrying the trigger; the DECLARATIONS themselves are guarded instead by the migration's own DO block (which REFUSES to install a declaration naming a column that does not exist — a typo would otherwise silently disable the guard) and by `updated_at_declarations_name_real_columns`, which re-checks them against the live catalog every CI run so the guard outlives the migration. It says nothing about a PLAIN `UPDATE … SET x = $1, updated_at = NOW()`: that shape was **measured at 24 sites on this tree and every one is a content write the trigger would stamp anyway**, so gating it would be 0% precision — which is why the check is scoped to `ON CONFLICT` upserts, where an unchanged re-write is the normal case rather than the exception. And it proves the stamp is ABSENT, never that the trigger's declaration for that table is RIGHT. Opt-out `// allow-explicit-updated-at: <reason>` on the reported line or within the 8 lines above.

  **#749 — the remainder #748 named and did not fix.** #748 replaced `get_execution` and repaired its fourteen call sites; it left FOUR sibling repository methods reading `workflow_executions` alone on the same two-valued shape, across six call sites — and stated so. Two were losing real data on the dev fleet the day this landed. **`tail_worker_logs` is the one that matters most, because it is a LOSS and not merely a wrong diagnosis**: `module_executions` and `module_execution_logs` carry NO foreign key to `workflow_executions` (unlike the CASCADEd `execution_events` / `workflow_execution_logs`), so the worker's own log lines SURVIVE the archival move — measured at **929 rows across 133 of 133 archived executions** — and the ownership gate was discarding every one of them behind "Execution not found or access denied. tail_worker_logs only supports workflow executions; …", a sentence false on all three clauses. `get_execution_lineage` answered the same about an archived anchor. The remaining four were LATENT and are stated as such (0 split trees, 0 workflows whose latest is archived, 0 approvals on archived rows) — each is a silent truncation the day the condition arises, and `parent_execution_id` / `root_execution_id` carry no FK at all, so a lineage link survives archival as a dangling id and a live-only walk truncates the tree while reporting the truncated count as the total. **The four are classified, not uniformly patched**, and the classification came from the SWEEP PREDICATE rather than from assumption: `archive_move_sql` selects `status IN ('completed','failed','cancelled') AND completed_at IS NOT NULL AND is_pinned = false`, so an archived execution is TERMINAL by construction — which is what makes `submit_workflow_approval` a REFUSAL (`archived_refusal`) whose direction was always right and whose diagnosis was not, and makes `watch_execution` a refusal too (its events were CASCADEd away, so there is nothing to watch). `tail_worker_logs` READS and stamps; the lineage walk reads BOTH tables and stamps each node with which one it came from; `get_workflow_id_any_user` (platform-admin audit chain) simply gains the archive read, since the WORM ledger it keys is untouched by archival and there is no archived-vs-absent claim for the caller to render differently. **`watch_execution`'s workflow branch was the sharpest**: reading the live table alone did not merely fail to find the latest run, it returned an OLDER one AS "the latest" with nothing marking it stale — reachable because the sweep skips pinned rows — so `lookup_latest_execution_for_workflow` is the one lookup here that CANNOT be live-first-archive-on-miss and is a single `UNION ALL` ordered across both (one round trip, two index probes). Everywhere else the archive query runs only on a live MISS. `tail_worker_logs` also needed its OWN note: stamping [`ARCHIVED_EVENTS_GONE`]'s "not retained past the archive window" above the retained logs would be a report contradicting itself. **Lint extension, MEASURED in both directions against a real `git worktree` of `origin/main` (NOT a `git archive` extract — leg (b) inventories via `git ls-files`, which returns nothing in an extract, so extract-based validation silently skips it):** leg **(a)** grew from one identifier to four (`get_execution_base` / `get_workflow_execution_owner` / `get_latest_execution_for_workflow`) — **3 findings on pristine main, 0 on the fixed tree**, precision trivially 100%. Leg **(b) was BUILT AND REJECTED**: extending its method alternation to the four names reports **1 of the 6 real call sites = 16.7% recall** on pristine main (only the lineage one), because the other five spell the collapse `Ok(_) =>`, `_ =>`, `.ok_or_else(…)`, a `None =>` forty lines past the call, or a message reading "No executions found for this workflow" — green over five of six defects is the gate-that-doesn't-gate shape (#624, checks 64/65), so it was not shipped. Leg **(c)** grew from one enum to the four archived-arm spellings now in the tree, AND its arm-header pattern from `[^=]*=>` to a same-line non-greedy run: the owner-lookup arms carry a `==` guard, which `[^=]*` stops dead at, so the old pattern **silently did not inspect them** — confirmed by running the old header against the mutation and watching it return nothing. Both (c) halves are mutation-proved on the fixed tree (unguarded arm, guarded arm, and a `_ =>` wildcard on `lookup_execution_owner`, each reported by line), and #748's own mutation still fires under the widened regex. **`get_workflow_id_any_user` keeps its name and `Result<Option<Uuid>>` signature, so NO lint leg covers it** — `execution_archive_read_tests::the_platform_admin_workflow_lookup_reaches_the_archive` does, and saying which instrument covers what matters more than implying the lint covers everything. The DB tests' burden is carried by eight MAIN-VOCABULARY twins run against a clean `origin/main` worktree with its own migrated database: **8 FAIL BY ASSERTION, 6 controls PASS, none fails by compile error** — and the `watch_execution` twin fails with a UUID on the left, i.e. main returns the wrong row rather than no row. **Stated limit inherited from #748 and re-confirmed here:** these tests drive the repository methods and the pure `classify_owner` / note renderers, NOT the handler bodies; a mutation that classifies correctly and then discards the answer inside `handle_tail_worker_logs`'s own match survives every test here and is caught only by leg (c).

  **Sub-leg 64b (#748, no new number — `--count` stays 81): a controller DB-harness binary must be in the runner list whose ENVIRONMENT matches its harness.** Leg 64 proves the union — the binary is named somewhere. The 45 binaries partition by an invisible property: `mod common;` needs `DATABASE_URL` (CTRL_TESTS supplies it); `mod test_helpers;` self-provisions a testcontainer (TC_TESTS supplies none). A `common` binary in TC_TESTS is green under 64 and dies in CI in **0.00 s** at `common/mod.rs:117` before any assertion — which is how #748's own first CI run failed. Measured before writing: post-fix 45 agree / 0 mismatch, pristine main 0 pre-existing — a population of exactly one, deterministic, 100% precision. Proven three ways against scratch copies of the runner (silent on the fixed tree; "OTHER list" on the pre-fix registration; "neither" when unregistered). Stated limit: literal array names and literal `mod` lines — a third harness or a renamed array is invisible until added. No opt-out.
  82. an actor-attributed mutation on the signed-RPC routes must sit behind the write-ceiling chokepoint — `actors.max_write_ceiling` is ONE control and #750 established that it must be checked on EVERY route to a mutation; #750 closed the `__memory_write__` envelope route and RECORDED the next one without fixing it. **The transport is why the crate cannot trust its caller**: these requests are HMAC-signed under `WORKER_SHARED_KEY`, which is FLEET-SHARED, so the signature proves the sender holds a key, not that the sender ran a gate — a worker booted without `TALOS_WRITE_CEILING_ENFORCED` (the mixed-fleet state `get_platform_info.fleet.write_ceiling.enforced_by = "some"` reports, which #752 calls "the dangerous one") refuses nothing locally, and the controller persisted whatever it sent. Every call to `persist_memory_with_metadata` / `forget_exact` / `talos_integration_state::execute_op` / `execute_guest_query` in `talos-rpc-subscribers/src/` must have `write_ceiling::gate` within the 60 lines above. **SCOPE is MEASURED, not stylistic**: the same four helpers are called from **59** other places in the workspace — MCP handlers, the engine node hook, `scaffold_actor`, consolidation/reflection — and those are the OPERATOR's or the PLATFORM's writes, which the ceiling deliberately does not speak to, so a workspace-wide version would be 59 false positives (same scoping principle as check 6 and check 50). **Measured in both directions against the real trees, not a synthetic mutation: 4 findings on pristine `origin/main` — exactly the four routes #754 fixed — and 0 on the fixed tree, 0 false positives.** Stated limits, each confirmed rather than inferred: TEXTUAL and WINDOW-bounded at 60 lines (60 because the database site's gate sits 51 lines above its call), so a gate hoisted further away reads as absent — a FALSE POSITIVE, the loud direction; it matches an ENUMERATED set of entry points, so a mutation issued through a NEW helper or raw `sqlx::query` is invisible, which is why `write_ceiling::write_ceiling_tests::complement_is_worker_local` sits beside it forcing any newly ceiling-gated WORKER op to be classified as controller-served or worker-local; and it proves the gate is NEAR the mutation, never that its answer is HONOURED — a `gate(..).is_refused()` whose result is discarded satisfies it, which is why `CeilingDecision` is `#[must_use]` and why the DB test asserts on ROWS rather than on replies. That last point is not hypothetical: an earlier version of that test asserted `reply.result.is_err()` on an INSERT into `actor_memory` that fails its NOT NULL constraints anyway, so **removing the database gate entirely left it green** — the only one of four mutations to survive, and it survived by being satisfied for the wrong reason. Opt-out `// allow-ungated-rpc-mutation: <reason>` within the 60 lines above the call, for a write that is genuinely the PLATFORM's rather than the actor's.


  75. whole-tree lint scans must prune second checkouts — a repo-root `find .` / `grep -r … .` inside this script descends into `.claude/worktrees/<session>/`, which holds OTHER branches' source. It is not merely noise: every path-anchored exemption here names a path relative to the repo root, so under a worktree prefix the ONE legal implementation stops being recognised and BYTE-IDENTICAL code is reported as a violation. **Measured 2026-09-02 on a tree with six sibling worktrees (5,518 extra `.rs` files): 110 red lines where the same tree alone produces 0 — 108 prefixed `.claude/worktrees/`, and the two that were not were the INFLATED summary count (`41 private copy(ies) of a SHA-256 → UUID derivation`, true value 0) and the failure verdict.** So the number an operator would act on is wrong in the same direction as the noise, and the run cost 4:05 instead of 2:10. This is a CLASS: eleven scans pruned `.claude` by hand and the ten added after them did not — checks 58/65(c), 68, 69, 71, 73 and 74b, the last of them two days old; three fired falsely and the other seven were latent, with 58/65(c) failing in the QUIET direction (a worktree copy supplies registration evidence, so an alert on a metric this tree never registers reads as covered). All 21 repo-root scans now share ONE definition — `TREE_PRUNE_FIND` / `TREE_PRUNE_GREP` at the top of the script — so the next scan inherits the answer instead of re-deciding it; per-check prunes (`target`, `vendor`, `node_modules`) stay at the site because they vary by check and are not about second checkouts. Three directions, because "uses the shared list" is worth only as much as the list being real and the detector seeing anything: **(a)** every repo-root scan statement names one of the arrays; **(b)** both arrays are non-empty and both name `.claude` (an emptied array would silence (a) at every site at once); **(c)** the detector must MATCH SOMETHING — a scan-shape change that made the walk unrecognisable would otherwise leave a green tick over zero statements, checks 64/65's lesson. **Verified by running the check against the ORIGINAL script: it reports all 21 repo-root scans and 0 after.** That 21 is the honest number and worth stating plainly rather than quoting the 10: the rule is the SHARED LIST, not "some prune", so the 11 hand-pruned sites are findings too — they spell the same intent four different ways (`'*/.claude/*'`, `'./.claude/*'`, `--exclude-dir=.claude`, and one that pruned `.git` but not `.claude`) and each spelling is a place the next copy can drift. Ten of the 21 were genuinely blind to `.claude`; the other eleven were correct and are now unable to become incorrect independently. Stated limits, confirmed by mutation: it is TEXTUAL and statement-scoped (line plus backslash continuations), so a scan whose root arrives in a VARIABLE (`find "$dir"`) is invisible — deliberately, since a scoped `$dir` is the common and correct case; it proves the array is REFERENCED, never that the reference sits in an effective position (`"${TREE_PRUNE_FIND[@]}"` after a `-print0` would satisfy it); and `rg` / `fd` / `git grep` are out of range — `git grep` needs no prune because it reads TRACKED files and a worktree checkout is not tracked here, which is why check 72 is not on the list. `.claude` is pruned WHOLESALE rather than just `.claude/worktrees/`: only two files under it are tracked (`hooks/session-start.sh`, `settings.json`) and neither is `.rs`, so the coverage cost is nil. Opt-out `# allow-unpruned-tree-scan: <reason>` on the statement's first line.
  85. "does this SQL mutate?" must have exactly ONE implementation — the question is asked on BOTH sides of `talos.database.query`, and the two sides answered it DIFFERENTLY. #757 fixed the CONTROLLER (an AST walk breaking on any nested non-`Query` statement) and left the WORKER — the documented PRIMARY fence — matching the STRING `"SELECT" | "EXPLAIN"` against `sql_validator`'s TOP-LEVEL statement label. sqlparser 0.53 + `PostgreSqlDialect` parses `WITH ins AS (INSERT INTO t VALUES (1) RETURNING a) SELECT * FROM ins` as a `Statement::Query`, so that label is `"SELECT"`, so the worker classified a `readonly` actor's INSERT as a READ and forwarded it; only the controller's newer gate stopped it. **Measured on pristine main, driving the real path (`validate_sql_with_policy` → the gate's own predicate): the INSERT and UPDATE CTE forms both returned "permitted as read", with plain `SELECT`/`INSERT` as passing controls.** The classification now lives in `talos-sql-classify` (a leaf crate: `sqlparser` and nothing else, `SqlAccess::{ReadOnly, Mutates{nested}, Unclassified}`, `Unclassified` failing closed) and both consumers call in; the worker gets its verdict from `ValidatedStmt.access`, computed off the AST the validator already parsed, so the classifier costs a tree walk and not a second parse. **The same measurement found a SECOND, wider hole in the same function family, on a different control**: `enforce_cte_mutation_policy` guarded its allowlist test behind `if !allowed_operations.is_empty()`, so an EMPTY allowlist fell through to `Ok(())` and admitted a writable CTE — while the top-level path refuses a bare `INSERT` under the identical configuration, `EmptyAllowlistPolicy::DenyMutations` being the production default whose documented contract is "only SELECT passes when the allowlist is empty". Not a corner case: `allowed_sql_operations` is hardcoded `vec![]` at EVERY dispatch site in the workspace, so the empty allowlist is the ONLY configuration the fleet has, and the bypass was live for every database-world module INDEPENDENT of the actor's write ceiling. Five legs: **(a)** the deleted private predicate `sql_stmt_type_is_read_only` must stay deleted (check 68(c)'s shape); **(b)** a file CALLING the `database-query` write-ceiling gate must name `talos_sql_classify` — without it, (a) is defeated in one line by re-deriving the verdict under a new name at the same call site (check 69(a)'s shape); **(c)** `sqlparser` may be a direct dependency of only the three crates that legitimately parse SQL, because a fourth classifier would be born in a fourth crate (check 67(b)'s shape); **(d)** no non-comment line may pair the literals `"SELECT"` and `"EXPLAIN"`; **(e)** the worker's SQL host file may not build a predicate out of `validated.stmt_type`. **Legs (d) and (e) exist because MUTATIONS beat everything else here, and that is the part of this entry worth remembering.** The first version of the worker tests drove a helper that RE-DERIVED `!validated.access.is_read_only()` instead of calling the gate, so reverting the gate's CALL SITE to the old inline `matches!(validated.stmt_type.as_str(), "SELECT" | "EXPLAIN")` passed all 635 crate tests and legs (a)–(c) — (a) pins an identifier the inline form never mentions, and (b) was satisfied because the file still named the crate elsewhere. That is `guard_that_passes_its_own_mutation` in this project's own notes. Three things closed it, and each covers what the others cannot: the decision was EXTRACTED into `write_ceiling_audit_target` so the expression the tests drive IS the expression `execute_query` evaluates (mutation M4, gutting that function, fails 2 tests); the call site's invertible boolean was REMOVED — the gate is now an `if let` over a function returning the audit LABEL, which also ties the string handed to `write_ceiling_refuses` to the call that decided to refuse, instead of fetching it separately from a field that means something else; and legs (d)/(e) grep for the two spellings a call-site revert takes, because a test can always be bypassed by inlining a different expression at the call site while a grep for that expression cannot. **A SECOND survivor was then measured and closed the same way**: a single-literal revert (`!matches!(validated.stmt_type.as_str(), "SELECT")`) beat the tests AND legs (a)–(d); leg (e) reports it at the mutated line, as it reports the `.then_some(...)` variant that survives the `if let` restructure. **Measured in both directions against a `git archive` extract of a4caecf9, reported as they came out: leg (a) 9 lines in 1 file there / 0 after; leg (b) 2 files there — of which only ONE is a defect, the worker's, the controller's being a correct implementation reported only because the shared crate did not yet exist for it to name — so 2-of-2 against the RULE, 1-of-2 as a BUG detector, 0 after; leg (d) 1 there / 0 after / 1 on the mutated tree; leg (e) 0 there (the pre-fix predicate took its argument as a bare `&str`, so leg (e) would NOT have caught the original bug — it is a REGRESSION guard for a seam the fix created, not a detector of what was there) / 0 after / 1 on each of the two mutated trees. Leg (c) ships at ZERO and is PROPHYLACTIC: it found nothing on either tree**, which is worth saying plainly rather than implying it caught something. **What was BUILT AND REJECTED on measurement**, so it is not rebuilt: the obvious detector — a `matches!` over `Statement::Insert | Update | Delete | Merge` outside the classifier crate — reports **20 lines across 2 files on the FIXED tree and every one is legitimate** (`statement_type`, `always_blocked_label`, `statement_returns_rows`, `is_ddl`, `controller_permits_data_statement`, `statement_type_label`), because those answer a DIFFERENT question — which statement KIND is this, for the allowlist, the audit target and the error text — whose right answer really is top-level only. 0% precision; enforcement-shaped noise. **Stated limits, each confirmed by mutation rather than inferred:** all five legs are TEXTUAL; (a) pins ONE identifier, so a differently-named private copy is invisible; (b) fires on the FILE not the call, so its opt-out also blinds that file to a future gate, and it proves the classifier is NAMED, never that the decision flows from it; (c) sees only direct `[dependencies]`, so a re-export is invisible; (d) pins the two-literal spelling, which the single-literal survivor above walked straight past — that is why (e) exists — and (e) is scoped to ONE file and pins the receiver `validated.stmt_type`, so a revert routed through a local binding (`let t = validated.stmt_type.as_str();`) evades it; closing THAT needs dataflow, not a grep, and the honest position is that the gate's shape (no boolean, one named decision, tests on that decision) is the primary guard and these legs are the cheap second copy. And NO leg can see the shape that already exists and is correct — `sql_validator::check_query_for_mutations` is a hand-rolled recursive walk over `SetExpr`, and a read-only verdict rebuilt in that style would evade all three (the guard against that is the shared crate's pinned `CORPUS`, not this grep). Two decisions are RECORDED rather than assumed, in named tests: `SELECT … FOR UPDATE` is `ReadOnly` (it takes row locks but writes no rows, and the enclosing transaction commits immediately), and function side effects (`SELECT nextval('s')`) are OUT OF RANGE for a statement-shape classifier — the worker's expression-level `check_disallowed_functions` deny-list is the surface that can see those. `EXPLAIN` moves from read to non-read, which changes NO live decision because `always_blocked_label` refuses every EXPLAIN before the gate (pinned by `explain_never_reaches_the_ceiling_gate`). F4, measured not asserted: sqlparser's own `DEFAULT_REMAINING_DEPTH = 50` refuses nesting past depth ~48, and in a RELEASE build a 3 500-deep 124 KB input parses to `Err` with no stack overflow on a 2 MiB (tokio worker default) or 8 MiB stack — the same input DOES overflow a 2 MiB stack under a DEBUG build, a `cargo test`/dev-binary hazard rather than a production one, which is why the depth test pins the RECURSION LIMIT (identical in both profiles) instead of asserting "no overflow" under a small stack, an assertion whose outcome the build profile would decide. Opt-outs `// allow-forked-sql-classifier: <reason>` (b), `# allow-new-sqlparser-dep: <reason>` (c); leg (a) has none — a second copy of this predicate has no legitimate form.
  86. a "never executed" predicate must not drive a destructive draft path — `execute_subworkflow_graph` runs a child IN-PROCESS and records no `workflow_executions` row (measured 2026-09-05: zero rows carrying `parent_execution_id`, live table and archive, platform-wide), so `NOT EXISTS (SELECT 1 FROM workflow_executions …)` does not mean *this workflow never ran*, it means *nothing in that table can tell you*. Three statements are built on it and two of them ACT: `fix_all confirm=true` DELETES irreversibly, and `session_start`'s auto-archive ARCHIVES with no confirmation. #758 fixed the 30-day dormant list, classified these two as "latent today — no draft child on the fleet", and **the first live report after it deployed listed the flagship's daily `team_gather` sub-workflow under a delete instruction** — the latency claim had been measured with the query that was already fixed. Two legs, because either alone is defeated: **(a)** FILE-scoped — any non-test file carrying the predicate must name the child-reference chokepoint (`scan_child_parents` / `talos_child_workflow_refs` / `ChildReferenceScan` / `child_protection_reason`). File-scoped and not windowed because the analytics SELECT feeds a delete decision made ~180 lines later and three crates away, which no window can see. **(b)** SITE-scoped on the DESTRUCTIVE verb — an `UPDATE`/`DELETE` statement carrying the predicate must have the chokepoint within 40 lines; without it, (a) lets a new destructive statement ride into an already-gated file. **Measured in both directions against a `git archive` of `origin/main`: leg (a) 2 findings (`talos-advanced-repository`, `talos-analytics-repository`), leg (b) 1 (`archive_stale_drafts`'s UPDATE) — every one real, 0 false positives — and 0 on the fixed tree.** Leg (b)'s statement-head walk starts ABOVE the predicate line and had to: the predicate's own `SELECT 1 FROM workflow_executions` was matching as the statement head, and **the first version of this leg therefore reported 0 on the pre-fix tree** — the gate-that-doesn't-gate shape (#624, checks 64/65) inside the guard for it, caught only because the leg was run against the real pre-fix tree instead of a mutation. Mutation-proved three further ways on the fixed tree: renaming the chokepoint away from the archive UPDATE fires (b) at that exact line while (a) stays silent (the file still names it elsewhere — which is precisely why (b) exists); a new destructive statement in a brand-new crate fires BOTH; and a tree where the predicate matches nothing at all FAILS LOUDLY rather than passing, since a check that matches nothing is a green tick over zero statements. **Stated limits, each confirmed rather than inferred:** both legs are TEXTUAL, so a predicate assembled with `format!()` or spelled differently (`NOT EXISTS(SELECT`, a `LEFT JOIN … IS NULL`) is invisible; **(a)'s file scope means one gated site vouches for every site in that file, and there is such a site TODAY** — `AdvancedRepository::get_draft_workflows`, deliberately left child-blind as a report-only path, sits in the same file as the gated archive method, so a fourth DESTRUCTIVE statement added to that file would be seen by (b) but not by (a) (it carries no opt-out marker precisely because (a) matches one file-globally); (b)'s 40-line window and 25-line head walk mean a reflowed statement reads as ungated — a FALSE POSITIVE, the loud direction; and neither leg can prove the scan's ANSWER is honoured, only that the chokepoint is named — a `protection_for(id)` whose result is discarded satisfies both, which is why the behaviour is pinned by `controller/tests/stale_draft_child_workflow_tests` driving the real `fix_all` planning path AND `confirm=true` against a real row. Opt-out `// allow-execution-blind-draft-path: <reason>` — file-globally for (a), within the 40-line window for (b).

  87. a `workflows` liveness predicate must name the shared home — `workflows` carries TWO columns that both claim to say whether a workflow is live and they are not the same fact: `is_enabled` (`20260314001600`) is the OPERATOR's pause toggle, `status` (`20260318000000`) is the LIFECYCLE. Neither writer touches the other's column — the six `UPDATE workflows SET status = 'archived'` sites never clear `is_enabled` and `set_workflow_enabled` never moves `status` — so, measured on the reference fleet 2026-09-07, **all eight archived rows still read `is_enabled = true`** (`active/t 17, archived/t 8, draft/t 11`). The hygiene report's dormant query predicated `w.is_enabled = true` with no status clause and listed every one of them under *"Consider disabling or deleting them with `batch_delete_workflows`"*: of the TEN workflows that advice named, EIGHT had already been retired by the operator it was advising. The predicate now has ONE home, the leaf crate `talos-workflow-liveness`, which renders the Rust predicate and its exact SQL twin (`live_sql` / `dispatchable_sql` / `retired_sql`), with `rust_and_sql_agree_on_every_status` EVALUATING the rendered fragment rather than comparing strings. **WINDOW-scoped, not file-scoped, and that is the whole design**: the four sibling queries in `talos-analytics-repository/src/lib.rs` already spelled the same predicate correctly a FOURTH way (`is_enabled = true AND (status IS NULL OR status != 'archived')` — the `status IS NULL` arm dead, the column being `NOT NULL`) in the SAME FILE as the defect, so a file-scoped rule — check 86(a)'s shape — would have been GREEN over it: four correct siblings vouching for a fifth site that forgot. **Measured in both directions: file-scoped reports 6 on pristine `origin/main` of which 3 are the `workflow_schedules.is_enabled` false positive (50% precision, shipping at 3 markers on correct code); window-scoped reports SEVEN, every one a real `workflows` liveness predicate, 0 false positives, and 0 on the fixed tree.** Stated honestly, and it matters: **7-of-7 against the RULE, 1-of-7 as a BUG detector** — the other six were CORRECT and merely unrouted (check 85(b)'s framing). Mutation-proved three ways: reinstating the dormant defect reports it at that exact line; a COMMENTED-OUT gate does not vouch (whole-line comments are stripped first — check 73's self-report trap, which cost this check one false finding on its own doc block before the strip went in); and a tree where the shape has vanished FAILS LOUDLY. That third leg needed a two-part tripwire and the first version got it wrong in the REASSURING direction — once a site is routed the literal `is_enabled = true` disappears from it, so a raw-literal-only tripwire reported "found nothing" on the fully-fixed tree (measured, not imagined); it now counts raw windows PLUS rendered `*_sql(` call sites. **Stated limits, each confirmed by mutation**: TEXTUAL and WINDOW-bounded, so a reflowed statement or one assembled from a fragment in another file reads as ungated — a FALSE POSITIVE, the loud direction; `workflow_schedules.is_enabled` (~55 references) is excluded by the window's own `workflow_schedules` test and `webhook_triggers`' column is spelled `enabled`, so both are out of range; it proves the home is NAMED in the window, never that the rendered fragment is the one bound into the query; and it says NOTHING about the 48 `status`-only sites, deliberately — nearly all are lifecycle filters (`status = 'draft'` for the stale-draft list) rather than liveness decisions, so a wider regex would be enforcement-shaped noise. **What it cannot reach, recorded rather than implied**: no EXECUTION path filters on `workflows.status` at all — proved with a scratch row against the verbatim scheduler due query, the post-due load, the webhook dispatch read, `resolve_by_capabilities` and `WorkflowGraphStore::get_graph`, all five of which returned an archived workflow. Latent on this fleet (the 8 archived rows have 0 enabled schedules and 0 enabled webhooks) and left alone as a fleet-wide behaviour change, not a report fix. Opt-out `// allow-split-liveness-predicate: <reason>` within the window.
  88. every static sqlx statement must PREPARE against the real schema — `sqlx::query("…")`, the FUNCTION form, takes a runtime `&str`. **NOTHING checks it**: not rustc, not clippy, and not CI's "sqlx offline cache (compile-checked queries)" job, which covers only the `query!` MACRO forms. Measured on this tree: **69** macro call sites against **1,904** function-form static statements, so the two sets are **disjoint by construction** and this check covers exactly the complement, not the overlap. A statement naming a renamed column, a dropped table or a relation that never existed therefore compiles cleanly, ships, and errors at request time — where a caller's `.unwrap_or_default()` renders it as an empty list. `AnalyticsRepository::list_workflow_webhooks` asked `webhook_triggers` for `endpoint_path` and `is_enabled`; that table's flag column is `enabled` and there has never been an `endpoint_path` column at all (the endpoint is DERIVED from the id), so `get_workflow_dependencies` answered `webhooks: []`, `webhook_count: 0` for every workflow since the rename — **a determinate negative over SQL that has never once executed**, the misleading-report class (74, 76, 79/79b, 81) with a new cause. Check 74's glob does not name that handler and it built no `Readings`, so neither leg saw it. **Measured in both directions against a real `git worktree` of `origin/main`: ELEVEN findings there, all eleven real, 0 false positives — and 0 on the fixed tree.** The whole-workspace scan (wider than this check's roots) found **16**; the five outside them are `controller/examples/`. The eleven span four distinct causes, which is why this is a check and not a one-line fix: a RENAMED column (the two webhook statements); a relation that NEVER existed (`workflow_audit_log`, `workflow_webhooks` — both read by methods with ZERO callers, both deleted); a table a sibling integration has and this one does not (`gmail_integration_audit_log`, so **every Gmail connect/disconnect event has been lost since the integration shipped**, logging an ERROR each time — migration `20260907120000` creates it, copied clause-for-clause from `slack_integration_audit_log`); a column a COMPLETED migration retired (`encrypted_key_v2`, which Phase 5 `20260424030000` renamed to `encrypted_key` — and that migration is FOLDED INTO THE SCHEMA BASELINE, cutpoint `20260705130000`, so the Phase-3/4 tooling could never run on any database this repository can produce; its own abort message told the operator to run the tool that can no longer run, and the module plus both examples are deleted); and a statement Postgres rejects **unconditionally** — `SELECT COUNT(*) … FOR UPDATE` in `talos-organizations`, under a comment reading *"Use a transaction with FOR UPDATE to prevent TOCTOU races. Lock the relevant rows and count owners atomically."* No bind, no schema and no data can make that run, so `remove_member` errored on **every** call and the **last-owner guard has never once been evaluated**; the fix locks the owner rows in a subquery and counts what was locked. **Two false-positive classes are excluded by RULE, not by a path list, and both were measured rather than assumed.** (a) `42P08`/`42P18` **indeterminate parameter type** (8 workspace-wide, 2 of them production): the probe prepares with no type list so the server must infer, while sqlx at runtime SENDS the type OIDs from the Rust bindings — proven by re-preparing the same statements with an explicit type list and getting `DEALLOCATE`, and corroborated live by check 70's own record of one of them demonstrably executing. Counted and reported, never failed on. (b) **test-created runtime tables** (11, every one of them): `rls_probe`, `rls_union_probe`, `rls_perm_probe`, `rpcwc_probe` are `CREATE`d by the binary that queries them, so `tests/` directories are out of scope. **Stated limits, each measured rather than inferred:** it is TEXTUAL, so a statement assembled with `format!` or reached through a variable is INVISIBLE — **32 such call sites in scope**, reported as a count on every run so the coverage claim is visible rather than implied, and this change itself moved TWO statements out of range by routing them through `talos_workflow_liveness::live_sql` (one home for the predicate beat static-ness, and a DB test drives both). **PREPARE proves a statement can be PARSED and PLANNED, never that it can SUCCEED** — and that gap is not hypothetical: `insert_published_internal_workflow` omits `workflows.module_uri`, which is `NOT NULL` with no default, so `plan_and_execute_workflow` failed at its first write (0 rows at `workflow_type = 'internal'` platform-wide) and this check reports it as clean. It was found by a DB test, not by the probe; constraints, triggers, RLS and permissions are all outside what a PREPARE can see. It also says nothing about a statement that runs perfectly and matches nothing — `WHERE w.status = 'published'` prepares fine (see the dated entry below). It is ENV-GATED (`TALOS_LINT_SQL_PREPARE=1` + a migrated `TALOS_SQL_PREPARE_URL`/`DATABASE_URL`), exactly like check 7's clippy, and `make test-integration` runs it against the DB it already builds so the gate is not merely opt-in; asked-for-and-unable-to-run is a FAILURE rather than a skip, and extracting ZERO statements is a hard failure too, because a check that matches nothing is a green tick over nothing (checks 64/65) — that arm fired for real during development when the roots were passed as one argument. Mutation-proved in four directions on the fixed tree: reverting the webhook column, reverting one `COUNT(*) … FOR UPDATE`, and deleting the retry-intelligence opt-out each fire at the exact line; the first of those initially read as a SURVIVOR and was a `sed` that never matched — printing the diff before believing the result is the discipline, not the result itself. Opt-out `// allow-unpreparable-sql: <reason>` within 8 lines above the call, for a statement deliberately kept un-runnable (`talos-retry-intelligence`'s `diagnose_failures` is the one live instance: zero callers, and the paragraph above it documents a denominator trap a future reviver must read).

- **Deleting a test file? Grep the CI workflows first.** `quality.yml` names individual integration targets by hand (`cargo nextest run -p controller --test <name>`), so removing a test file makes `cargo test --no-run` fail with `no test target named <name>` (exit 101) even though the code is fine — it failed the whole Rust-unit check in PR #567 after the circuit-breaker self-test was deleted. `grep -rn "<test_name>" .github/ Makefile` before deleting.
- **A registered Prometheus metric with zero increment sites is DEAD — an alert on it silently never fires.** `talos_workflow_executions_total` was registered in `talos-metrics` but never incremented anywhere, so the failure-rate alert built on it would never have fired (found + fixed 2026-07-24: wired it at the `mark_execution_completed`/`_failed` chokepoints in both repo crates, counted only on a real row transition). When adding an alert, confirm the metric has a live `.with_label_values(&[…]).inc()` (or `.inc()`) call site — not just a `CounterVec::new` + `registry.register`. Now enforced by structural lint **check 58**.
- **In PromQL, ABSENT and ZERO are different, and every common alert idiom (`== 0`, `< N`, `rate(...) == 0`, `a / (a+b)`) reads absent as "no match".** So a detector can be silenced by exactly the condition it detects: `NoWASMExecutions: rate(wasm_executions_total[30m]) == 0` could only fire on a worker that HAD executed and then stopped — never on the cold-dead case, which is the one that matters (found live 2026-08-02, alongside the same shape in `TalosBackupRestoreDrillFailed`, where a drill that had never run made "no successful drill in 14+ days" unfireable). Fix it on BOTH sides. **Producer:** a `CounterVec` emits nothing until a label set is touched and an OTEL instrument emits nothing until its first measurement, so pre-seed at 0 — but ONLY closed, compile-time-known label combinations that a live call site actually writes (seeding a combination nothing increments implies a wired signal that does not exist, and any caller-derived label value is an unbounded-cardinality DoS surface). **Consumer:** add an `absent(x) or …` arm where the absent series is one Talos itself is supposed to produce — and NOT where absence legitimately means "not applicable" (`vault_core_unsealed` on a cluster without Vault, `kube_*` without kube-state-metrics, `up` for a job check 65(a) already gates). An absent arm must keep the alert's existing severity. **`up == 1` certifies reachability, not production**: the meta-detector for "target green, producing nothing" is `WASMMetricsPipelineDead`, and it is kept off a permanently-red state by being gated on the target being up AND on the producer-side seeding — a permanently-firing alert trains operators to ignore red, which is the same defect. `observability/alerts_test.yml` drives these transitions through `promtool test rules`; it is NOT CI-wired (no Prometheus toolchain on the runners) and says so in its own header.
- **`make lint` ≠ pre-commit.** The pre-commit hook runs compile-only; clippy (`-D warnings`) and rustfmt run at pre-push / CI. Run `TALOS_LINT_CLIPPY=1 make lint` before pushing — recurring surprises this session: `trivially_copy_pass_by_ref` on serde `skip_serializing_if(&T)` helpers (allow it — serde mandates the ref), needless late-init (`let x; if … {x=…}` → `let x = if …`), and ref-to-ref on `Option<&T>` params.
- **`scripts/smoke.sh` end-to-end probe.** Runs every public path against a deployed cluster (`/health`, `/auth/csrf` cookie seeding, `/graphql` with full CSRF round-trip, `/ws` handshake, `/mcp`); optional Phase-B encryption write→read round-trip with `SMOKE_AGENT_TOKEN` + `SMOKE_ACTOR_ID`. `deploy/k3s/install.sh` invokes it as §9.1 at the tail of every deploy — a failed smoke warns but doesn't abort install. Run manually any time with `make smoke BASE_URL=https://…`.
- **When introducing a new top-level path on the controller**: add a matching `location` block to the chart's nginx ConfigMap, OR mark the route `// no-nginx-route: <reason>` (kubelet probes, in-cluster scrape, etc.). The lint check 2 catches drift either way; the smoke test fails fast in production if the path is supposed to be public but nginx routes it to the SPA.

## Image publishing
- **CI OIDC publish is canonical** (Jul-2026): `gh workflow run main-publish.yml --ref main`. The workflow's `ci-gate` job REQUIRES a green `quality.yml` run for the exact SHA (bypass: `skip_ci_check` dispatch input), builds all three images for linux/amd64 (frontend from `frontend/` context — repo-root context breaks its Dockerfile), pushes via `GITHUB_TOKEN`, cosign-signs each digest with the **workflow's OIDC identity** (Fulcio keyless — NOT any operator's personal identity, killing the per-operator regexp-widening problem), and emits the `TALOS_*_DIGEST` block in the run summary. Clusters pin `^https://github\.com/OWNER/talos/\.github/workflows/main-publish\.yml@` (trailing `@` load-bearing, same rule as template-publish). Runbook: `docs/second-operator-publish-runbook.md`. The local script below is the documented fallback.
- **Auto-triggers stay OFF** (May-2026 decision): the four image/publish workflow files (`ci.yml`, `release.yml`, `main-publish.yml`, `template-publish.yml`) are gated to `workflow_dispatch:` only — every publish is an explicit act. The `push:` / `pull_request:` / `tags:` blocks are commented out, not deleted.
- **Exception — `quality.yml` IS auto-triggered** (Jun-2026): the heavy correctness gates too slow/networked for the pre-push hook — full Rust test suite, the env-gated **integration** tests (`make test-integration`: RLS isolation, crash-recovery, …) that `cargo nextest` alone skips, the networked RUSTSEC advisory scan (`make audit`), and a frontend lint+test backstop — run on `pull_request` to main + a nightly `schedule` + `workflow_dispatch`. It deliberately excludes the expensive image-build jobs (those stay in `ci.yml`). This is the unbypassable backstop for the gates the (opt-in) pre-push hook can't cover; it exists because the gated integration suite silently rotted (a security RLS suite sat red on main for days — PR #181/#182).
- **`scripts/publish-images.sh`** is the local FALLBACK build path (was canonical until Jul-2026). Mirrors `main-publish.yml`'s contract: builds via `docker compose build controller worker` plus a separate `docker build -f frontend/Dockerfile` (the compose file points the frontend at `Dockerfile.dev` for local-dev), pushes `:main-<sha>` (+ `:main-latest`) to `ghcr.io/<owner>/talos-*`, captures digests via `docker inspect`. Flags: `--no-push`, `--no-sign` (signing default ON — see below), `--allow-dirty`, `--skip-ci-check`, `--service NAME`, `--platform linux/amd64` (default, mandatory on Apple Silicon → x86_64 deploys), `--update-env PATH`. Emits a copy-pasteable `TALOS_*_DIGEST=…` block for `/etc/talos/install.env`.
- **Publish gate (2026-07-01)**: pushing requires (a) a **clean tree** (dirty publishes REFUSED; `--allow-dirty` for debugging, tags suffixed `-dirty`) and (b) a **green `quality.yml` run for HEAD**, verified via `gh run list --commit`. `quality.yml` gained a `push: branches: [main]` trigger so squash-merged main commits have a run bound to their own SHA (PR runs attach to the PR head SHA). Bypass is explicit: `--skip-ci-check` / `TALOS_PUBLISH_SKIP_CI_CHECK=1`.
- **Signing is DEFAULT-ON** (flipped 2026-07-01; provenance is the default act, skipping it the deliberate one — the batched single-OAuth-tab flow removed the cost that justified default-OFF). Opt out with `--no-sign` or `TALOS_PUBLISH_SIGN=0`. The script BATCHES all images into a single `cosign sign --yes` invocation — one browser tab, one OAuth token, three Fulcio cert issues. Fallback to per-image loop only if the batched call fails (old cosign versions, etc.).
- **Signing identity binding**: CI-published images carry the WORKFLOW URI identity (issuer `https://token.actions.githubusercontent.com`) — the stable, operator-independent pin clusters should prefer. Locally-signed images instead carry the operator's GitHub OAuth identity (issuer `https://github.com/login/oauth`), NOT a workflow URI; production clusters with Sigstore enforcement enabled (`TALOS_SIGSTORE_REQUIRED=true`) admitting locally-signed images need their identity regexp widened to the operator's email pattern PER HUMAN — the exact problem the CI path removes. The chart-level signing contract is otherwise identical (cosign + Fulcio + Rekor public-log entry).
- **Secret rotation auto-bounce (MCP-1231)**: every dependent pod template (controller / worker / NATS / Neo4j / postgres) carries a `checksum/<secret>-data` annotation rendered from `helm lookup` over the live secret content. When install.sh rotates the bootstrap / postgres-credentials / neo4j-auth secrets out of band, the NEXT `helm upgrade` notices the data hash changed and rolls the consumer pods automatically. Pre-MCP-1231, every rotation required manual `kubectl delete pod talos-{nats,neo4j,postgres}-0` rituals — observed three days in a row during the in-cluster Postgres rollout.
- **Dirty-tree publishes are refused** by default (see publish gate above). With `--allow-dirty` the tags are suffixed `-dirty` so they can never be confused with a clean-main image. Don't deploy `-dirty` builds to production.
- **CI gates** (lint, test, structural lint) run locally via `make lint` and `cargo test --workspace`. Run `make hooks` once per clone to install the git hooks (`core.hooksPath=.githooks`): the **pre-push** hook runs `make lint` (fmt + structural + `clippy --workspace --no-deps -D warnings` + offline cargo-deny) **and `make lint-frontend`** (frontend eslint + prettier + vitest) so the CI-parity gates can't silently regress between manual runs, and the **pre-commit** hook keeps the fast secret/migration/compile checks on every commit. Emergency bypass: `git push --no-verify`. Still run `cargo test --workspace` + `make lint` before `bash scripts/publish-images.sh`.

## Postgres deployment modes
- **Default (`postgres.enabled: false`)** — operator wires `DATABASE_URL` in the bootstrap Secret pointing at a managed Postgres (Neon, RDS, Cloud SQL, etc.). This is the recommended path for any multi-node or production deployment. `install.sh` requires `TALOS_POSTGRES_URL` in this mode.
- **In-cluster (`TALOS_USE_INTERNAL_POSTGRES=yes` → `postgres.enabled: true`)** — chart deploys `pgvector/pgvector:pg17` as a single StatefulSet replica on a `local-path` PVC. The pgvector team's official image (Debian-based, derived from `postgres:17`) is required — NOT stock `postgres:17` / `postgres:17-alpine` — because the Talos schema uses `vector(N)` columns and migration `20260406000001` fails with "type vector does not exist" against any image without pgvector compiled in. The migration's `CREATE EXTENSION IF NOT EXISTS vector` is wrapped in `EXCEPTION WHEN OTHERS THEN` so it silently no-ops on stock postgres, then a later migration trips loudly on the missing type. Single-user / homelab path. Limitations: no streaming replication, no PITR, no off-host backup (daily `pg_dump` to a separate local PVC, retain 7 days). NOT for multi-node production.
  - Credentials live in a separate `<release>-talos-postgres-credentials` Secret (NOT in `talos-bootstrap`) so the Postgres pod only mounts its own user/password/db, not the full bootstrap blast radius (Vault tokens, master DEK, LLM keys, etc.).
  - Postgres runs as uid/gid **999** — the postgres user in the Debian-based pgvector image. The StatefulSet has its own `securityContext` block instead of inheriting the chart-wide 10001 default; pod-side `fsGroup: 999` matches the PVC ownership. Switching FROM `postgres:17-alpine` (uid 70) requires wiping the PVC because the old data dir is chowned to uid 70 and the new pod can't write into it.
  - postgresql.conf tuning lives in `templates/postgres/configmap.yaml` and is calibrated for a 4 GiB shared VM (shared_buffers=256MB, effective_cache_size=512MB, max_connections=60, scram-sha-256 password encryption). Override via `postgres.config.*` in values.
  - NetworkPolicy restricts ingress to three clients: controller, migrations Job, postgres-backup CronJob. Workers DO NOT reach Postgres directly — they route through signed NATS-RPC to the controller. Same isolation rule as Neo4j.
  - `helm.sh/resource-policy: keep` on both the credentials Secret AND the backup PVC so `helm uninstall` doesn't wipe the password or daily dumps.
- **Both Secrets MUST be in lockstep** if internal mode is used. To rotate: delete `talos-bootstrap`, `<release>-talos-neo4j`, AND `<release>-talos-postgres-credentials` together, then re-run `install.sh`. Deleting any subset puts the cluster in an inconsistent state — controller refuses to start when the Secrets disagree.

## Cache Patterns
- **TTL-bounded cache = read-path eviction + periodic sweep.** Read-path `remove()` handles active users; sweep handles users who went dark. Without the sweep, memory grows monotonically with distinct-users-ever-seen. See `SecretsManager::sweep_expired_llm_keys` wired into `main.rs` at the sweep interval.
- **Cache invalidation on write paths must be scoped.** Use `RETURNING id, owner_user_id` to scope invalidation to the affected user; fall back to `invalidate_all_*` only for legacy rows with NULL owner. Avoid "flush everything" on every write.
- **Short TTL for rotation-sensitive caches** (e.g. 60s for LLM keys) so rotations propagate quickly. Longer TTLs (5 min for DEKs) are fine for cryptographic material that rotates via explicit operator action.

## OCI template registry
- **Two source-of-truth modes, mutually exclusive.** `TALOS_REGISTRY_URL` set → controller pulls catalog from OCI registry, skips disk seeding entirely. Unset → disk seeding from `module-templates/` baked into the image. Don't mix; the previous "both run, OCI overrides" model created a 5-min regression window on every pod restart where the disk baseline overwrote operator-curated versions.
- **Discovery is via index artifact, not `/v2/_catalog`.** GHCR / GAR / ECR don't expose `_catalog`. The publish workflow pushes a `talos-tools/_index:latest` artifact whose **config blob** is JSON `{"templates": [{"name": "...", "tag": "..."}]}` listing every template. `registry::sync::IndexConfig` parses it. Self-hosted Docker registries fall back to `/v2/_catalog` automatically. Adding a new template = re-running `template-publish.yml`; the index is regenerated.
- **Publish via the controller binary, not a CI re-implementation.** `controller publish-templates --templates-dir ... --output ...` reuses the production `CompilationService` (cargo-component scaffold, WIT bindings, dependency allowlist). The GH Actions workflow `template-publish.yml` mounts the controller image and runs the subcommand — CI never re-implements the scaffold, so it can't drift. Updating compilation logic only happens in one place.
- **WASM digest verification on every pull.** `verify_oci_layer` (worker/src/main.rs) recomputes sha256 of pulled bytes and compares to the manifest's declared digest. Mismatch = fail closed (don't execute, don't cache, return JobStatus::Failed). Manifest with no layer descriptor = accept-with-warning. Pure function so it's unit-tested without a registry. Don't introduce a "trust mode" that bypasses this — the digest check is the only thing standing between a corrupted/MITM'd registry and arbitrary WASM execution.
- **Redis OCI cache has a 24h TTL** (`OCI_CACHE_TTL_SECS`). Without it, distinct module URIs accumulate forever. Tag-based URIs refresh daily; digest-based URIs (immutable) re-cache the same bytes harmlessly. Cache writes happen ONLY after digest verification passes.
- **Auth model**: anonymous works for public packages (recommended for templates — they aren't secrets, signing provides trust). Private packages: set `OCI_REGISTRY_USERNAME` + `OCI_REGISTRY_PASSWORD` in worker AND controller envs (PAT works as the password for GHCR). Bearer-token OAuth challenge flow is NOT implemented in the controller's reqwest paths or in the worker — `oci_distribution::Client` handles it for the controller's `pull_manifest_and_config` (uses oci-distribution), but the worker's reqwest fallback paths only support Basic.
- **Sigstore signing is the runtime trust boundary.** Every OCI artifact (templates + index) is `cosign sign --yes`ed in the publish workflow using GitHub Actions keyless OIDC. The worker `verify_oci_signature` shells out to `cosign verify` BEFORE the OCI pull body is processed — verification failure with `TALOS_SIGSTORE_REQUIRED=true` returns `JobStatus::Failed` and the WASM is never executed nor cached. Three policies: `Disabled` (dev), `Audit` (verify+log+continue, migration window), `Required` (verify+refuse, production). `cosign_verify_argv` is a pure function so the security-critical command construction is unit-tested without invoking cosign — DO NOT bypass `--certificate-identity-regexp` or `--certificate-oidc-issuer`; either omission lets a valid Sigstore signature from any other workflow on any other repo pass verification. **Two-layer attestation:** the `_index:latest` artifact itself is signature-verified BEFORE its config blob is parsed (`talos-registry/src/sync.rs::try_pull_index`), AND each template entry is verified again at template-fetch time. A `Disabled` policy in dev would let an attacker replacing the index alone redirect template names → attacker-controlled tags; the startup gate (`enforce_production_sigstore_policy_explicit`) refuses to boot in prod without an explicit policy choice, so the dev-only fall-through is non-exploitable in any real deploy.
- **Sigstore identity regexp pins to the workflow URL.** Format: `^https://github\\.com/OWNER/talos/\\.github/workflows/template-publish\\.yml@`. Without the trailing `@`, an attacker who creates a fork named `template-publish.yml-evil.yml` could match. The OIDC issuer pin (`https://token.actions.githubusercontent.com`) restricts to GitHub Actions tokens specifically. Cosign is bundled in the worker Dockerfile at a pinned version so verification doesn't depend on operator's PATH or apt repository state.

## HTTP middleware & router rules
- **`cors_middleware` short-circuits ALL `OPTIONS` requests** (`controller/src/main.rs::cors_middleware`). It builds an empty 200 response and returns immediately, never calling `next.run`. Consequence: an `OPTIONS` preflight cannot trigger ANY downstream middleware (including `csrf_protection_graphql`). Don't try to seed cookies or run validation logic via OPTIONS — pick a real GET endpoint.
- **`tower_cookies::CookieManagerLayer` on a sub-router merged AFTER the outer `CookieManagerLayer` is unreliable.** When a sub-router is `.merge`d into the parent app and you re-add `CookieManagerLayer + cookie-modifying middleware` inside that sub-router, `Set-Cookie` headers can fail to appear in the response (root cause not pinned down — likely a layer-ordering interaction with axum's response mapping). For cookie writes on routes that bypass the main cookie layer, build the `Set-Cookie` header by hand in the handler. See `seed_csrf_handler` for the reference pattern.
- **Probe and exempt routes need their own Extension layers.** `probe_routes` is merged AFTER the rate-limit layers (so kubelet probes can't be 429'd). The Extension layers (`db_pool`, `redis_client`, `nats_client`) attached to the main app DON'T propagate to merged sub-routers — re-attach them on the sub-router or the handlers panic with "Extension not found". The `mcp_router` follows the same pattern.
- **Per-IP rate-limit identification MUST use RFC 7239 right-to-left X-Forwarded-For walk** (`rate_limit::extract_client_ip`). Reading the leftmost entry is exploitable: any client behind a trusted proxy can prepend a fake IP and the server attributes their requests to it. The walk skips trusted-proxy entries from the right; the first untrusted entry is the real client.
- **Probe paths are exempt from rate limiting two ways**: (1) architectural — `probe_routes` merged after rate-limit layers; (2) defence in depth — `is_rate_limit_exempt_path()` early-returns from `rate_limit_middleware` and `global_rate_limit_middleware`. With Traefik on `externalTrafficPolicy: Cluster`, kube-proxy SNATs all external traffic to a single node IP, so without the exemption a busy site evicts kubelet probes from the per-IP bucket → pod marked NotReady → 502 cascade.
- **Helm controller probes use `/live` and `/ready`, not `/health`.** `/live` is a trivial process-alive check (no DB/Redis/NATS calls) — a Postgres hiccup can't restart the pod. `/ready` returns 503 only when Postgres is down (Redis/NATS report degraded but still 200). `/health` is the user-facing combined check, kept for the frontend's `seedCsrfCookie` and ad-hoc curl.
- **WebSocket handlers MUST extract Origin from the request HeaderMap** and pass it into `ws_auth::handle_websocket_auth` — passing `None` makes EVERY WS connection fail in production with "missing Origin header" because `is_production()` requires the header. The handshake still returns `101` (the upgrade succeeds), then the socket is immediately closed by `handle_websocket_auth`, which the browser surfaces as `WebSocket connection failed:` with no detail.
