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
- Per-subject concurrency semaphore; every completion is COUNTED on `talos_rpc_calls_total{subject,outcome,class}` + `talos_rpc_duration_seconds` and logged on `target: "talos_rpc"` with split `queue_ms` / `exec_ms` at a level derived from `RpcOutcome::class()` (see the 2026-09-09 entry — until then this line said "metric events" and there was no metric)

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
- `consolidated` — `talos-memory-consolidation` summaries (added to
  `SYNTHETIC_MEMORY_KINDS` 2026-09-10; that list also drives the
  graph-extraction skip, so consolidated rows no longer auto-extract —
  stated trade-off, since consolidation retires the source rows)

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

## Engineering log — the decisions, kept

Everything below is a DIGEST. The narrative that produced each decision moved
VERBATIM to `docs/engineering-log/` (index: `docs/engineering-log/README.md`)
because at 5,109 lines this file cost ~137k tokens at every session start and
every agent brief, and it was growing ~200 lines per package. **The split is by
KIND, not by age**: a rejected lint, a measured population, a `latent on this
fleet` claim and a `deliberately NOT` are the record that stops the next session
redoing work already done, so they stay HERE; the story of how each was found
moved out. `scripts/check-engineering-log.py` proves mechanically that no line
was lost and that every decision marker in the archive is named below.

**What the split bought, measured rather than claimed** (so nobody re-measures):
5,109 → 1,465 lines but 549,796 → 307,742 BYTES, i.e. **44%**, not the 71% the
line count suggests — the removed narrative is hard-wrapped at ~78 columns while
what stayed is not. ~137k → ~77k tokens per read. And the honest consequence:
the 88 lint checks are now **52% of this file's bytes** (114 lines of ~1,400-char
paragraphs), so the next attempt to halve this file has to start there, where the
inline documentation IS the specification. An age-based archive was REJECTED and
must stay rejected: 124 lines of this file carried a decision marker and they are
woven into the prose, so cutting by date takes the decision with the story.

**Rules for adding to this file.** A new package writes its decisions into the
digest that owns the class, and its narrative into that class's archive file (or
a new one, with a README row). If you cannot tell whether a paragraph is a rule
or a story, it is a rule — leave it here.

### The workflow-liveness / child-run family → [`2026-09-05-workflow-liveness-and-child-run-ledger.md`](docs/engineering-log/2026-09-05-workflow-liveness-and-child-run-ledger.md)

**The class.** Operator-facing reports asserted a determinate negative for a
state the reader could not represent — the misleading-report class (checks 74,
76, 79/79b, 81) applied to `workflows`. Three pairs of columns/tables each
carried two facts under one reading: `readiness_computed_at` vs
`readiness_scored_at`; `workflows.status` vs `workflows.is_enabled`; and
`workflow_executions` vs a sub-workflow child that writes no row there. RFC 0012
(`sub_workflow_runs`, P1/P2/P3) is the answer to the third.

**Decisions that must not be re-litigated.**
* **The readiness columns are deliberately NOT collapsed** and the reason is
  measured: the two scorers are not the same function (`get_readiness_exec_data`
  excludes acknowledged failures, the background loop counts them), one timestamp
  cannot say which produced the stored number, and a
  `readiness_scored_at = COALESCE(...)` migration would relabel 35 background
  scores as breakdown scores. The READER was taught to read both
  (`classify_readiness_state`, one home).
* **`workflows.status` and `workflows.is_enabled` are deliberately NOT collapsed
  and there is NO migration flipping `is_enabled` on archived rows** — same
  argument: two writers record two different operator acts, and a backfill would
  relabel eight archives as pauses that never occurred. The predicate has ONE
  home, the leaf crate `talos-workflow-liveness` (`is_live` / `is_dispatchable` /
  `not_retired`); `dispatchable_sql` is deliberately NOT the dispatch gate's
  predicate (it also requires `is_enabled`, an unauthorised second behaviour
  change), and `not_retired_is_weaker_than_dispatchable` pins the two apart.
* **Should `execute_subworkflow_graph` record a child `workflow_executions` row?
  Answered NO**, measured before deciding: ~225 child runs/day (98.6% one
  workflow); **163** `FROM workflow_executions` occurrences across 28 non-test
  files of which exactly **2** filter on `parent_execution_id`, so recording
  children would silently double-count in 161 places (every fleet total, error
  rate and cost aggregate); `budget_precheck` counts execution rows, so a parent
  with a child would be billed twice; and the retention sweep would split one
  tree across two tiers. Shape B — a separate narrow table — shipped instead.
* **A child's unmeasurable components are NOT renormalised.** Two renderings were
  rejected and stay rejected: scoring the two components 0 of 100 (the
  determinate negative), and scaling the measurable 30 up to 100 (which would
  report a documented child as **100/100 fully production-ready** on zero
  evidence — worse, because it is confident in the reassuring direction). A child
  scores *N of `CHILD_MEASURABLE_MAX` (=30)*. What is unified is the BASIS,
  deliberately NOT the reliability INPUT. `below_50_count` excludes unmeasurable
  children with the exclusion disclosed; **`avg_score` is deliberately NOT
  adjusted** (a population-wide SQL mean the page cannot correct) and says so.
* **`LEDGER_MIN_RUNS` is 3**, argued from #762's own reasoning: 1 promotes on one
  observation; 10 keeps a child that has demonstrably run nine times on a
  denominator whose stated reason is "nothing can measure this"; 3 is the
  smallest number from which a success RATE is a rate. The floor protects the
  DENOMINATOR claim, not the arithmetic.
* **Does a child's `draft` status mean anything at runtime? No, and this is worth
  knowing before anyone "fixes" it by publishing.** `execute_subworkflow_graph` →
  `WorkflowGraphStore::get_graph` reads the child's DRAFT `graph_json` column with
  no version join, so `publish_version` changes nothing about how the parent runs
  it and the "publish or delete" advice is half no-op and half destructive.
  ARCHIVING a child, by contrast, DOES stop it being dispatched since the narrow
  gate — so the unattended auto-archive sweep is now the most severe of the three
  destructive draft paths, and the child-reference exclusions on it are
  load-bearing.
* **`ChildRunLedger::since()` is deliberately NOT user-scoped** — the question is
  a deployment fact; a per-user `MIN` would render UNKNOWN forever for a user who
  has legitimately never dispatched a child. **UNKNOWN is not zero** and **a child
  run is NOT charged to the actor's hourly execution budget** — two
  non-negotiables, recorded so nobody "fixes" them.
* **`execution_cost_rollup` as a child-run proxy is KEPT and DEMOTED, not
  deleted**: it is the only thing that can speak for the period before the
  ledger's first row. Its measured worst case is **0%** recall (one child whose
  parent ran 5085 times in 30 days has ZERO rollup rows and a proxy timestamp 45
  days old). Once `ledger_since` predates the 30-day window it can be removed.
* **`get_latency_percentiles_ms` / `get_performance_metrics` are deliberately NOT
  collapsed into the unified SLA read** — they answer the latency DISTRIBUTION of
  SUCCESSFUL runs, and folding a failed run's duration into `duration.p50` moves
  a number an operator reads without being asked. `get_sla_window_stats` and
  `SlaWindowStats` were DELETED rather than kept as a projection (they returned
  `Option`, so a failed read and an empty window were one value).
* **Folding zero-invocation children into `get_workflow_reuse_stats`' main list
  was rejected** — that list is RANKED by the count they do not have; they get a
  second list, `parent_dispatched`.
* **The scheduler does NOT disable a schedule row on an archived-workflow
  refusal.** Option (b) — disable on first refusal with a WARN — was rejected:
  archiving is REVERSIBLE, so a self-disabling schedule makes un-archiving
  silently not resume. The per-tick line is DEBUG (check 69's reason), the
  durable signal is `talos_dispatch_refused_total` plus
  `scheduler_dispatches_total{outcome="denied"}` — **DENIED, not SKIPPED**.
* **Sites deliberately NOT gated by the archived-dispatch gate**, argued rather
  than omitted: (1) resume and crash recovery (refusing would strand a waiting
  approval gate — the gate is about what the platform will START); (2)
  `test_workflow` / `test_workflow_draft` / GraphQL `testWorkflow` (an operator
  testing one named workflow is not the platform deciding to run it, and refusing
  removes the only way to check before un-archiving); (3) module replay.
* **`__ops_alert__` and `__ml_distill__` remain ungated by the write ceiling** —
  a DECISION, argued in the RPC-layer section above, not a remainder.
* `AdvancedRepository::get_draft_workflows` is deliberately left child-blind
  (report-only, no destructive action) and carries no lint marker; the reasoning
  is in its own doc comment. **Its consumer is no longer child-blind (2026-09-11):**
  the reasoning had said the display's "worst advice is publish it: a no-op for a
  child" — and that no-op was `session_start`'s `priority_action` on every
  session of the reference fleet (`cos-team-recall`, child of
  `pa-chief-of-staff`), while the hygiene report beside it said the opposite.
  The brief now runs the child scan over the ≤5 listed drafts and ANNOTATES
  (`child_status`, `publish_is_no_op`, `runs_as_child_of`, a truthful
  `next_step`) rather than hides; children never count toward the publish
  nudge; a failed scan renders `child_status: "unknown"` on every entry and
  keeps the nudge, never a silent "not a child". Pinned by three DB tests with
  controls (a non-child shaped draft keeps the recommendation; a child of an
  ARCHIVED parent is publishable again, because the scan's parent predicate is
  the shared liveness home). **Deliberately NO force flag** on the auto-archive
  sweep, mirroring `fix_all` — the escape hatch is an explicit operator action.
* **30 + 30 = 60 days** is the execution lifetime and is kept deliberately
  (decision 2026-09-06); `get_archive_policy` renders both tiers from
  `resolve_retention_policy`, one parse.

**Measured and NOT changed** (so the population is visible rather than
rediscovered):
* A graph-blind execution read misleads **26** surfaces, not one.
* **No execution path in this workspace filtered on `workflows.status` at all**
  before the narrow gate — proved with a scratch row against five verbatim
  production reads. `is_enabled` is enforced in RUST, never in SQL, at four
  places, and `bulk_trigger_workflow` / `enqueue_workflow` had none.
* The hygiene REPORT counts a substantive draft as `deletable` while `fix_all`
  excludes it — report/decision running the other way, advice a human reads,
  recorded rather than changed.
* `set_workflow_sla_threshold` still accepts a row with BOTH thresholds NULL;
  the SLA report's denominator includes runs still IN FLIGHT, disclosed.
* `controller/src/bootstrap/background.rs` is `mod bootstrap` inside `main.rs`,
  so no integration test can call the readiness or SLA loop — deleting the loop's
  `child_scans` lookup leaves every test green. Stated, not implied.

**Latent on this fleet, stated plainly** (latent is not live, and it cuts both
ways — the "no draft child on the fleet" claim was **refuted by the report's own
output in the first run after it deployed**, because the query used to measure it
was the one already fixed):
* The substantive-draft rule: ZERO additional skips (36 workflows, 11 drafts, 2
  with no execution row, one candidate at any window ≥7 days).
* The archived-dispatch gate: the 8 archived rows have zero schedule rows and
  zero webhook triggers, and there are **ZERO archived children under enabled
  parents** — measured WITH A CONTROL (dropping the archived filter returns 6
  real parent→child mentions). `resolve_by_capabilities` is the ONE site that is
  NOT latent: all 8 archived rows carry non-empty `capabilities` and that
  resolver is `ORDER BY updated_at DESC LIMIT 1`, so a retired workflow could be
  the WINNING candidate.
* The four RFC-0012 dispatch kinds P1 could not record; the `is_enabled` trigger
  gate (nothing is currently disabled); the `get_archive_policy` jsonb drift
  (`system_settings` held no rows at all); the lineage `child_runs ≥ 1` case; the
  15-minute SLA loop.
* `get_frequently_executed_unscheduled`'s sub-workflow exclusion is **vacuous on
  the reference fleet today** — `HAVING COUNT(we.id) >= 3` already excludes every
  pure child, so it bites only a hybrid, of which there are zero.

**Lints: one shipped, five measured and rejected.**
* **Check 87 SHIPPED** (`--count` moved to 87): *a `workflows` liveness predicate
  must name the shared home*. FILE-scoped it reports 6 on pristine main of which
  3 are the `workflow_schedules.is_enabled` false positive (50% precision) and it
  would have been GREEN over the defect once any one of four correct siblings in
  the same file named the home. WINDOW-scoped it reports **7 on pristine main,
  0 false positives, 0 on the fixed tree** — **7-of-7 against the RULE, 1-of-7 as
  a BUG detector**.
* REJECTED — *"a reader that scores or counts from `workflow_executions` must
  consult the child scan"* (`--count` stays 86): file-scoped 23 of 27 non-test
  files, nearly all legitimate; narrowed to five reader methods it reaches 7 call
  sites at ~71% precision and would ship at 2 markers; recall against the ~26
  graph-blind surfaces is **27%**; and decisively it is blind to the background
  loop, which reads executions with raw `sqlx::query_as` — a gate green over the
  most consequential site in its own class.
* REJECTED — *"a `workflows` read that feeds dispatch must name the liveness
  home"* (`--count` stays 87): the 35 dispatch reads share no SQL shape with ~40
  report reads (~50% precision at best); file-scoped it reports the 33 files
  carrying any `FROM workflows` and ships at ~25 markers; and it is green over
  its own defect, because every gate site now names the crate.
* REJECTED — *"the substantive predicate has one home"* (`--count` stays 86):
  1/1, trivially 100% precision, population ONE.
* REJECTED — *"`talos_config::archive_after_days()` may be read only inside the
  resolver"* (`--count` stays 86): 2 non-test sites, 1 real, 1 legitimate
  (`history_window_days`), 50% precision over a population of two.
* REJECTED — *"the ledger must be written"* (`--count` stays 86): population ONE
  chokepoint. And the whitespace-run candidate: the correct-house-style rule fires
  everywhere; the defect rule still reports the 17 legitimate sites on the fixed
  tree — 0% precision at zero, 17 markers on correct code.
* **No metric was added** to the 15-minute SLA loop and that is a measurement,
  not an omission: the function has no `TalosMetrics` handle, so a series means
  threading the registry into `spawn_late_background_tasks` for a loop that is
  latent here. The unreadable-window signal is therefore prose-only and cannot be
  alerted on.

**Two measured SURVIVORS left open**: setting the SLA report's
`child_runs`/`ledger_since` to `None`, and passing `None` for the risk check's
ledger evidence, both leave every test green. The RISK one self-discloses
(`reason: "ledger_not_consulted"`); the REPORT one is SILENT and its honest guard
is the live read after deploy.

### The swallowed-read / fail-open family → [`2026-09-07-swallowed-reads-and-fail-open-gates.md`](docs/engineering-log/2026-09-07-swallowed-reads-and-fail-open-gates.md)

**The class.** An awaited repository read collapsed into a default, where the
default becomes a count, a list, a verdict or a "not found" that a caller acts
on. Measured, classified and burned to zero over five passes; the read-side
companion inventory is `docs/swallowed-reads-inventory.md`, rendered by the
checked-in `scripts/lint-swallow-classify.py` + `scripts/swallow-read-verdicts.py`
(checked in because two earlier detectors were lost with their worktrees, and a
CLAUDE.md sentence must not cite an artefact the merge discards). Also here: the
MCP per-tool instrument (#786) and its outcome/class partition (#789).

**The population, so nobody re-measures.** 210 collapsed reads at the start
(110 claims / 67 decorative / 32 fail-closed / 1 detector FP; per spelling
`.unwrap_or_default()` 66, `.unwrap_or(<literal>)` 55, `.ok()` 32,
`match { Err(_) => default }` 26, `if let Ok(..)` 24, `.unwrap_or_else` 7) →
193 → 175 → 164 → 153 → **121 sites, 0 claim**. The residue is 60 decorative,
37 fail-closed, 31 false-positive and 1 nominal fail-open that is the repaired
`dlq_updates` narrowing. **"Zero claims" means zero of the population this
detector can see** — it is TEXTUAL, so a collapse reached through a helper in
another crate or applied to an already-resolved local is invisible, and
`if let Some(..)` over an Option-returning read is out of range.

**The rule the class produced.** A gate that cannot read its rule must REFUSE; it
must never GRANT. A report that cannot read a field renders `null`, never `0` or
`[]`, through `talos_measurement::Readings`. One `Readings` per report — a second
construction SHADOWS the first and publishes "complete: every field in this
report was measured" over a nulled field.

**Decisions.**
* **The MCP instrument's labels are NOT pre-seeded**, and the cost is pinned by a
  test so the argument cannot go stale: 19 lines per histogram series; 2356 bytes
  for the first `(tool, outcome)` pair and 1656 for each additional one, moving to
  2941 / 1996 when #789 added the `class` label; the full **~320 × 4** product
  measured at #786 is ≈ 1,280 pairs ≈ 2.1 MB / ~25,600 lines, a 35× scrape — and
  six outcomes since #789 make it worse, not better. Nothing alerts on
  the series, so absent ≠ zero does not apply. If an alert is ever written, seed
  the pairs THAT alert selects, never the product.
* **The COUNTER half of that instrument IS pre-seeded since 2026-09-11, and the
  reason is a defect the no-pre-seed argument did not consider.** A counter
  whose first sample is already `1` loses that increment to `increase()` /
  `rate()` — there is no `0 → 1` edge to see — so an unseeded per-tool counter
  under-counts by one per `(tool, outcome)` per PROCESS LIFETIME, and a tool
  called once per lifetime reads **zero forever** under the idiom every
  dashboard uses. Measured on the reference fleet over a 7-day window with
  thirteen controller restarts: `increase(talos_mcp_tool_calls_total{tool=
  "session_start"}[7d])` = **0**, the per-lifetime first samples sum to **15**,
  and the current lifetime's log shows the one call its instant value reports.
  The HELP text's "an absent pair means not called since process start" was
  true of the INSTANT read and silent about the rate read. So
  `talos_mcp_handlers::tool_labels::seed_tool_call_series` seeds
  `talos_mcp_tool_calls_total` at 0 over the closed product — declared tools ∪
  the two sentinels × six outcomes — from the controller bootstrap right after
  `set_global`, ONE text line per pair. **The HISTOGRAM stays unseeded**, exactly
  as #786 decided: 19 lines per pair is the 2.1 MB argument, and its `_count`
  is not the series to read call volume from — that is what the counter is
  for; latency quantiles do not need the first call. Cost is MEASURED by
  `seeding_costs_what_the_decision_assumes`: **195 825 bytes over 2 130 lines
  (91 B per line)**, i.e. the 76 KB controller scrape becomes ~272 KB — a 3.6×
  scrape against the histogram product's 35×; it re-derives if a seventh
  outcome or a large batch of tools lands. The talos-metrics cost pin's
  FIRST-pair number moved 2941 → 3459 because both HELP texts grew; the
  MARGINAL 1996 the histogram decision rests on is unchanged. The seed lives in the
  handler crate because the closed tool set is that crate's build-time
  registry; `talos-metrics` cannot name it without inverting the layering,
  and its own cold-registry cost test stays true (a bare `TalosMetrics::new()`
  still exports no per-tool series). Both HELP texts now say which series to
  read for which question.
* **Cardinality is closed by the COMPILER, not by convention**:
  `canonical_tool_label` returns a `&'static str` borrowed from
  `declared_tool_params()`'s own key, with `catalog_template` and `unknown`
  sentinels; the guard is POINTER equality. `outcome` is an enum. Buckets are
  `exponential_buckets(0.001, 2.0, 16)` — the house 15 tops out at 16.384 s,
  below the 30 s target.
* **`class` is a third label that adds NO series** (a pure function of `outcome`),
  and it exists so an alert rests on the same predicate the log level does rather
  than on a hand-maintained outcome alternation a seventh outcome would fall
  outside of. Verified over the table AND over a real registry.
* **The MCP error KIND travels out of band** (`#[serde(skip)]` on
  `JsonRpcResponse::error_kind`): the OPERATOR needs the denied/failed split and
  the CALLER must not get it (an existence oracle), and re-assigning wire codes
  would move bytes MCP clients depend on. A `task_local` is lost by `tokio::spawn`
  and mislabels a construct-and-discard; a reserved key inside `result` rests on
  a strip running. **The LOG LEVEL was measured and deliberately NOT partitioned**
  — #787 changed a level to fix NOISE (53% of WARN volume); the MCP line is one
  per call at one level by design, and `class` joins it as a FIELD.
* **The Helm chart is deliberately NOT changed for `pg_stat_statements`**, with
  the cost stated: `shared_preload_libraries` is a POSTMASTER GUC, so on that
  chart's single-replica StatefulSet enabling it is a full database outage for a
  pod restart, plus a fixed shared-memory allocation. An operator's decision.
* **`rotateEncryptionKey` PROPAGATES** an unreadable count (`1` was never a
  placeholder — it is the version number an operator tracks, and `0` renders no
  toast at all); **`clone_actor` does NOT** (the actor is already committed), so
  `memories_copied` becomes an `Option` and an UNKNOWN count now RUNS the
  embedding backfill rather than skipping it.
* **The ~363 genuine `-32000` failures were deliberately NOT marked
  `mcp_failed`** — their default is already `error`, so it is 363 lines of diff
  for no behaviour change. **The nine `"Model not found"` sites in `ml.rs` were
  NOT marked `NotFound`** and this is the sharpest limit of that package: they are
  written `let Ok(Some(m)) = … else`, which routes a READ FAILURE into the
  not-found branch, so marking them would assert a determinate negative in the
  instrument. **The instrument cannot be more precise than the handler's own
  read.** 102 constructor sites remain open (25 not-founds, 10 refusals, 67 with a
  runtime-variable message).
* **The lint pre-flight in `run_sandbox` was never a gate** —
  `compile_to_wasm_with_config` runs the identical `analyze::lint_source_code`
  pass and alone enforces the dependency allowlist and cargo-audit — so refusing
  would take the tool off the air on its most likely `Err` (the 60 s compilation
  semaphore). What was wrong was the SILENCE; it WARNs now.
* `Ok(None)` from the capability-world ceiling read deliberately keeps today's
  behaviour, matching MCP-545: the column is `TEXT NOT NULL DEFAULT
  'minimal-node'`, so `Ok(None)` can only mean "no such actor row", and refusing
  would make the authoring gate stricter than the runtime one.

**Latent, stated plainly.** Both `fail_execution_from_worker` remainder sites
(`webhook_triggers` holds ONE row with `module_id IS NULL`; the `talos.results.*`
observer is "mostly dormant"). Both capability/embedding heal loops
(`embedding IS NULL` = 0, `capabilities = '{}'` = 0 today — they fire on freshly
created or imported workflows). `remove_member`'s last-owner guard, on a
deployment with 1 `organization_members` row and 0 non-personal organizations.

**Lints: none added, `--count` stays 88.** Every candidate, with its numbers:
* *"a report handler must not default an awaited read"* (widening check 74's glob
  to every handler): **73 on pristine main, 61 claims — 83.6% precision**, which
  is not the problem; it would ship at **62**, i.e. a ratchet with a baseline,
  and check 52's own rule is do NOT re-add a baseline. What ships instead costs no
  check number: **sub-leg 74b's scope is DERIVED** (any function constructing a
  `Readings`), so a handler enrols itself by adopting the ledger — and 74b fired
  on the first lint run after the fixes, at a `JoinError` defaulting a filesystem
  scan. The way to extend the coverage is to fix a handler, not widen a regex.
* *"an enforcement decision may not be taken from a defaulted read"*: cannot be
  spelled textually — the three worst gates were `if let Some(..)`, and widening
  the binding leg to `Some(..)` takes it from **20 to 69** sites of which **3**
  are the gates, ~6% precision.
* *"a function may construct at most ONE `Readings`"*: population **1 → 0**.
  Its sibling *"a ledger must be attached"* is worse: 30 constructions against 29
  `attach` calls, and the one difference is legitimate — 1 false positive, 0 real.
* *"a `mod common`-harness test binary must not hand-roll an `McpState`"*:
  population FOUR in one directory; there is now exactly one `pub async fn
  mcp_state`.
* *"a caller of `fail_execution_from_worker` must derive `error_type`"*:
  population TWO.
* *"a metric label value must be `&'static`"*: not expressible — `Box::leak`
  yields `&'static str` from a request string, so the type is not the property.
* *"a new `tools/call` transport must call the instrument"*: population THREE
  call sites already funnelled through one `pub` wrapper.
* *"a refusal must not be constructed with the failure constructor"* (BUILT as
  `scripts/lint-mcp-refusal-constructor-candidate.py`, kept so the numbers can be
  re-derived): **258 sites on main, ~225 real (≈87%) — and 68 on the FIXED tree**,
  43 false by construction. It ships as a ratchet with a baseline; narrowed it
  still leaves ~28, **which are precisely the sites deliberately left alone** —
  so it would pressure a future author into asserting a determinate negative in
  the instrument. **A gate that pressures you toward the defect it is named after
  is worse than no gate.** The structural alternative was priced too: making the
  kind a REQUIRED parameter is **1583 call sites**.
* *"the CLAIM verdict as a lint leg"*: 0 claim / 0 unclassified on the fixed tree
  and 32 of 34 on main, and it still fails on three independent measurements — a
  revert at a RECLASSIFIED site is completely green (the opt-out key is
  `(file, function, callee, spelling)`, which cannot tell the pre-fix expression
  from the post-fix one); the two mutations it catches are caught only because
  the table still carries the PRE-fix verdict; and the ratchet arm fires on every
  new collapsed read whatever its verdict — packages 29 and 31 each ADDED two
  detector artefacts on CORRECT code.
* The whitespace-run guards were measured and rejected twice: a literal-scoped
  grep reports 6 on main (66.7%) and **2 on the fixed tree**, both legitimate; a
  render-time collapse at `mcp_text` hides the defect rather than preventing it
  and **would have covered two of the four at most**. Later re-measured with the
  checked-in `scripts/lint-whitespace-runs.py`: **200 literals carry a ≥5-space
  run and only 5 are defects** — ~2.5% precision, and even the mid-sentence
  narrowing ships at 1 marker on correct code. **The CAUSE is now known**: a `\`
  at the end of a line inside a Python `'''…'''` string is a Python line
  continuation, so an edit script writing Rust `\`-continuations through a
  non-raw triple-quoted string silently EATS them. Use a raw string.
* Relaxing an "exactly once" metric-delta assertion to `>= 1.0` was REJECTED —
  "exactly once" is what proves ONE record site writes both series; a
  `SHARED_SERIES` mutex serialises the tests instead.

**Measured SURVIVORS.** `MA7b` (the module-dependents INDIRECT scan) survives its
DB binary and is caught only by check 74b — the two reads name the same columns
of the same table, so no schema failure separates them. `M9` (reverting one of
eleven `-32601` admin refusals) survives every test, because driving those needs
a non-`*` `AgentIdentity` plus platform-admin state; the honest guard is the live
read after deploy. `M8` is a NO-OP, not a survivor. `dlq_updates` gets no test.

### The audit-chain verifier → [`2026-09-06-audit-chain-verifier-identity.md`](docs/engineering-log/2026-09-06-audit-chain-verifier-identity.md) and [`2026-09-07-dispatch-attempt-chain-partition.md`](docs/engineering-log/2026-09-07-dispatch-attempt-chain-partition.md)

**The class.** PRESENCE IS NOT FUNCTION at the identity layer: the WORM audit
bucket's verifier resolved credentials through the `AWS_*` chain, which on every
deployment is the WRITE-ONLY controller identity, so chain verification had
NEVER once succeeded — 48,946 prefixes written, 37 errored sweeps per hour, zero
verified chains, and the `Err` arm incremented nothing. Then: the first sweep
that ever ran called an identical redelivery "possible tampering", and a
controller re-dispatch of one `job_id` wrote a second chain under one prefix.

**Decisions.**
* **Do NOT widen the writer's policy to "fix" verification.** A writer that can
  also list and get is a writer that can survey and target what it wrote. The
  verifier is a separate identity (`MINIO_VERIFIER_USER`, `audit_read_only`)
  built from an EXPLICIT credentials provider with **no `load_defaults` on the
  path**. The writer/verifier split is asymmetric ON PURPOSE: `process_batch`
  dedupes within a batch and CANNOT dedupe across batches, because that means
  reading the prefix. Cross-batch copies are classified at the verifier.
* **`security_audit`'s `audit_chain_verification` weight is 0**, argued from
  scratch: the grade bands are ABSOLUTE against a 100-point total, so an
  eleventh weighted check re-grades every deployment and makes every earlier
  score incomparable. The zero is not decorative — a broken arm is `Fail` +
  `RoundTrip` + CRITICAL and lands in `status_counts.fail`.
* **`talos_audit_chain_last_verified_ok_timestamp_seconds` is deliberately NOT
  pre-seeded** — a zero seed reads as 1970 and would fire every staleness rule on
  a healthy cold boot; `TalosAuditChainNeverVerified` carries an explicit
  `absent()` arm instead and is gated on the sweep having run.
* **Unverifiable is not verified-bad**: `talos_audit_chain_unverifiable_total` is
  a SEPARATE series from `talos_audit_verification_failures_total`, and
  `TalosAuditChainUnverifiable` is `warning` — it says the CONTROL is not
  working, not that the ledger is bad. **Nothing alerts** on duplicate deliveries
  or on multi-attempt jobs: at-least-once delivery and a re-dispatch are the
  transport and the platform working as designed.
* **The ledger is keyed per JOB and the operator asks per RUN; both grains are
  reported and neither is folded into the other** (`roll_up_by_workflow_execution`,
  WORST OUTCOME WINS). `LEDGER_KEY_SPACE` is named in every report so nobody has
  to guess which table an id belongs to.
* **`dispatch_attempt` is a PARTITION key, NEVER a genesis input** — an old chain
  and a new one are verified by one rule from the same genesis. It uses the
  conditional-append signing idiom, so an all-default request is byte-identical
  on the wire AND in its MAC and **every object already in the bucket keeps
  verifying**. **Deploy ordering: WORKERS ROLL FIRST OR TOGETHER.** Old controller
  + new workers is completely inert; new controller + old workers is safe for
  first dispatches and REFUSES retries (fail-closed, bounded by the rollout
  width, 0–4 `node_retrying` events/day).
* `PipelineJobRequest` is deliberately unchanged — the chain path writes no audit
  chain at all, so a `dispatch_attempt` there would partition nothing.
* **The ledger's key space is WRITE-ONCE, and the chain runner was moving it
  after the seal (2026-09-11).** Found by re-verifying the 318 chains from the
  window in which the sweep had counted four `stage="chain"` failures three days
  after the partition fix: three failed, all `genesis_mismatch` at seq 1, all
  sealed by the worker under `genesis(job, job)` while the verifier expected
  `genesis(run, job)`. The worker hashes the ids ON THE WIRE, and every
  STANDALONE builder (module-bound webhook, DLQ replay, gmail, GCP, gcal push)
  signs `workflow_execution_id = job_id` with a NULL run on the module row;
  `talos-engine/src/workflow_chains.rs` then `UPDATE module_executions SET
  workflow_execution_id = <chain run>` to "link the trigger" — so every
  module-bound dispatch that fired a chain read as tampering, and the "0 of
  48,577 unbound rows" measured on 2026-09-06 was itself this rewrite hiding the
  population. Now: the link lives on the CHAIN RUN's row
  (`workflow_executions.triggered_by_module_execution_id`, live + archive +
  `ARCHIVED_EXECUTION_COLUMNS`, rendered by `get_execution_lineage` as
  `chain_trigger_module_execution_id`; no FK, #749's rule), the UPDATE is gone,
  and `partition_sweep_rows` reads a NULL run id as the standalone contract —
  `LedgerTarget::genesis_workflow_id()` returns the job id itself — so those
  rows are VERIFIED and disclosed as `ChainSweepStats::standalone` rather than
  dropped as `unbound`. A standalone job rolls up under its own id (a run of
  one). Guards: `controller/tests/chain_run_linkage_tests` (CTRL_TESTS) drives
  `insert_chain_execution_row` on a NULL-run module row and asserts the module
  row is untouched, the run row carries the link, and the sweep verifies the
  row under `(job, job)`; `talos-audit-event` pins the defect as a unit test
  (the same sealed chain passes under `(job, job)` and fails with
  `GenesisMismatch` under `(run, job)`); the security audit's round-trip probe
  offers a standalone job too, under its own genesis. **Not changed, stated**:
  the three historical rows keep failing if ever re-swept, since their column
  was already moved — forward-only, like the partition. Enumerate the ledger's writers by what the WORKER hashes, not
  by what the database later says.

**Measured and NOT changed / latent.** `module_executions.workflow_execution_id`
is NULLABLE and such a row cannot be verified — **0 of 48,577 rows platform-wide**,
so LATENT; it is COUNTED (`ChainSweepStats::unbound`) rather than filtered out of
sight, and `partition_sweep_rows` returns `(targets, unbound)` so a caller cannot
obtain the targets without the count. The compose `minio-init` never created
`MINIO_WORKER_USER` — dead env, closed separately. The chart's `minio-provisioning`
Job remains LATENT: there is no production environment. Historical prefixes stay
CONFLICTING — both copies carry no attempt field, so `DuplicateSequence` is the
correct answer for them and the fix is forward-only.

**Populations worth keeping.** 196 prefixes (0.40%) carried more than one
terminal anchor — 35 byte-identical, 161 conflicting, and **a second boundary is
the whole difference**, because `AuditEvent::timestamp` is whole seconds. Of
those, ~150 are CONTROLLER re-dispatches, not in-worker retries. `MAX_JOBS_PER_SWEEP`
moved 500 → **2000** (population is ~3.3× larger; a verification is ~30 ms).

**Lints: none added, `--count` stays 86.** *"the verifier must not use the
writer's credentials"* — population ONE, and the structural answer is stronger
(a distinct env name, an explicit provider, and a test that reads the access key
id out of the SigV4 header the SDK actually put on the wire, because
`Config::credentials_provider()` is DEPRECATED and returns `None` unconditionally,
so the obvious config-readback assertion would have passed vacuously).
*"a conditional-append signing segment must have a non-default wire snapshot"* —
4 segments, 1 has one, so it ships at 3. *"`ExecutionLedger::new*` must be the
producer's constructor"* / *"only above the retry loop"* — occurs ONCE in
non-test worker code. *"a `ChainBreak` consumer must branch on
`is_tamper_evidence`"* — 3 lines, none a verdict; `ok` is computed in one place.

**The measured SURVIVOR**: reinstating a per-attempt `ExecutionLedger` inside the
worker's retry loop leaves all 639 crate tests green — the anchor's only visible
effect is a NATS publish. The honest guard is the live read after deploy.

**And the fix would have made the report WORSE**, found by driving the real
verifier rather than by reasoning: with read-capable credentials the same
execution returned `ok=true, total_events=0`, because `verify_chain` over an
EMPTY set answers `ok == true`. The sweep was enumerating `workflow_executions`
while the writer keys on `module_executions.id` — **200 of 200** recent prefixes
are module-execution ids, **0 of 200** workflow-execution ids. Repairing the
identity alone would have turned 37 loud WARNs into 37 silent `verified_ok`.

### Artefacts that describe a system that does not exist → [`2026-09-07-artefacts-describing-a-system-that-does-not-exist.md`](docs/engineering-log/2026-09-07-artefacts-describing-a-system-that-does-not-exist.md)

**The class.** A credential, four documented env vars, a checked-in GraphQL
snapshot and an improvements list each LOOKED like the thing they named and were
not it. None is a vulnerability; each is a statement an operator acts on that had
been false for weeks. (W1) a REQUIRED `secretKeyRef` for a principal that does
not exist and a value the worker has no reader for — removed end to end, and on
upgrade the stale Secret keys select on nothing. (W2) `S3_ENDPOINT` and friends
configure the WIT object-storage host functions, NOT the audit ledger;
`docs/configuration-reference.md` is now stated to be the AUTHORITATIVE list.
(W3) `frontend/schema.graphql` was six weeks stale with a 186-line diff;
`talos_api::schema_sdl()` is now the ONE construction and a TEST pins it —
**a lint could only compare text to text**, because the comparison needs the
COMPILED schema and `scripts/lint-structural.sh` has no Rust build on its default
path. `schema.ts` needed its OWN gate (`npm run codegen && git diff --exit-code`),
deliberately NOT in `make lint-frontend`, which skips itself when
`node_modules` is absent — and a gate that skips is not a gate. (W4) the
readiness improvements list told a ledger-measured child to "execute the workflow
at least once"; `build_readiness_improvements` no longer receives the execution
count at all. (W5) check 55's scope widened to `controller/src/bootstrap/` +
`main.rs` (5 of 5 occurrences there are sqlx row reads, 0 serde_json).

**Latent**: the `.env`-generator break is reachable only from
`workflow_dispatch`/manual paths that have not run since #767.

**A lint was built, MEASURED and REJECTED; `--count` stays 86.** *Every backticked
`UPPER_SNAKE` token in `docs/deployment.md`'s env tables must be read somewhere.*
It reports **2 of 49 tokens** on pristine main and neither is an `S3_*` — because
the `S3_*` four DO have a reader, just not the one the doc claimed. **The detector
is green over the entire defect it was written for**, and it reports the same 2 on
the fixed tree. What it DID surface: `GRAPHQL_MAX_DEPTH` / `GRAPHQL_MAX_COMPLEXITY`
are documented as tunables and are hardcoded `limit_depth(15)` /
`limit_complexity(5000)` — the documented depth default was not even the live
value. No knob was invented; the rows now say what is true.

**Recorded remainder**: `controller/src/bootstrap/` + `main.rs` hold 63
`tokio::spawn` sites and 62 discard the `JoinHandle`; there is no
`std::panic::set_hook` anywhere. (Closed by the supervision work below, which also
corrects that 63 to 54.)

### SQL that has never once executed → [`2026-09-07-statements-that-never-executed.md`](docs/engineering-log/2026-09-07-statements-that-never-executed.md)

**The class.** `sqlx::query("…")` takes a runtime `&str`, so a statement naming a
renamed column is invisible to rustc, to clippy and to CI's sqlx offline cache
(which covers only the `query!` MACRO forms). Three surfaces asserted a
determinate negative because the SQL never ran: `webhooks: []` from a statement
that cannot PREPARE (`webhook_triggers` has no `endpoint_path` column and never
did — the endpoint is DERIVED from the id, which is why `webhook_endpoint_path`
now has one home); a hygiene filter on `w.status = 'published'`, a value whose
only writer stamps `workflow_type = 'internal'` in the SAME INSERT that the next
clause EXCLUDES — **self-contradictory, not merely unmatched**, and the same
literal was in the A2A agent card; and three trigger paths giving three different
answers. Now gated by **check 88**.

**Decisions.** `talos_workflow_liveness::is_dispatchable` is the trigger gate —
**deliberately NOT `not_live_reason`**, because a DRAFT must stay dispatchable
(11 of 36 workflows are drafts, 4 with enabled schedules) and gating on liveness
would create a NEW disagreement in place of the one being closed.
`OrchestrationError::WorkflowNotLive` is a new variant rather than a reuse so the
exhaustive matches name all four mapping sites. `WorkflowDisabled` is KEPT for
`replay`. Two behaviour changes, both new refusals, both stated plainly.

**Latent / not done.** The `is_enabled` gate is functional but latent — nothing is
currently disabled, so the only refusal this can produce today is the archived
one. No live trigger was fired against an archived workflow to demonstrate the
pre-fix behaviour, because that would EXECUTE it on the operator's only
environment; the evidence is the code, the schema and the fleet counts.
**A PREPARE probe cannot see a constraint**: `insert_published_internal_workflow`
omits the `NOT NULL` `workflows.module_uri`, so `plan_and_execute_workflow` failed
at its first write — found by a DB test, not by the probe.

### Failures nobody can see → [`2026-09-07-failures-nobody-can-see.md`](docs/engineering-log/2026-09-07-failures-nobody-can-see.md)

**The class.** Not a misleading report — a MISSING one. A push channel bound to a
module that no longer exists failed every delivery with a log line that said
nothing; a background loop can panic or simply stop with no metric, no audit
event and no restart; and the signed-RPC data plane had a function named
`record_rpc_metric` that recorded no metric.

**Decisions.**
* **Nothing is restarted, deliberately.** Restarting a loop whose panic is
  deterministic would spin, and deciding per-task whether a restart is safe is a
  separate change. What the instruments buy is that the death is SAYABLE.
* **A declined start is not a stopped loop, and the TYPE says which.**
  `TaskExit::{Declined(DeclineReason), ShuttingDown, LoopEnded}` — a genuine
  `loop {}` has type `!` and coerced, so every real loop compiled unchanged and
  the COMPILER enumerated the population that could return. `declined` and
  `shutdown` log at INFO and are excluded from the alert;
  **`shutdown` is deliberately not folded into `declined`**, because three
  delegate bodies run for the whole process lifetime and calling that "declined"
  would assert they never ran. `completed` keeps the ERROR and the alert.
* **Supervise the loops, not their launchers.** `WorkerFleetManagement` was
  DROPPED from the enum rather than left as a series nothing can increment. Four
  WORKER-side pure tickers are recorded and NOT supervised: `BackgroundTask::ALL`
  is what the CONTROLLER pre-seeds, so a worker-side variant seeds five
  controller series nothing there can increment — supervising them costs a
  PROCESS PARTITION of the shared enum, not one line, and the epoch ticker costs
  more again (four tests `abort()` its handle, and `spawn_supervised` returns the
  OUTER handle). `talos-jobs::start_processor` had zero callers workspace-wide and
  was recorded rather than wrapped; the crate was DELETED 2026-09-11. Three controller-side pure tickers ARE
  supervised for panic ATTRIBUTION only, and that must not be read as closing a
  silent-death gap they do not have.
* **Three of the eleven supervised loops are config-gated ABOVE their spawn**, so
  their series sit at 0 on a deployment that has not enabled them. That is NOT
  check 58's defect — this process can leave that state by configuration. The
  gate was deliberately left above the spawn rather than moved inside the body to
  manufacture a `Declined`.
* **`create_watch`'s module-binding gate: two operator `event_kind`s, ONE caller
  sentence** — splitting "no such module" from "not yours" in the reply is a
  module-existence oracle. `Unreadable` is a SEPARATE, retryable 503. **The
  RENEWAL path is deliberately NOT gated**: it re-uses an already-admitted
  binding, and refusing because the module was deleted meanwhile takes a LIVE
  watch off the air rather than stopping a new one being created wrong.
* **`build_report` and `HygieneService::new` take the push-channel readout as a
  REQUIRED parameter** — with a builder, deleting the two wiring lines left every
  test in the workspace green while the report silently stopped mentioning push
  channels. `PushChannelReadout::NotConsulted` is SILENCE, not zero. A
  `PushChannelRow` carries no push token, no endpoint and no payload.
* **The RPC instrument's seed set is 64 pairs, not 126**: each subject's declared
  outcomes are exactly what ITS subscriber can pass. The cross product would seed
  62 combinations no call site can reach — check 58's own defect. The HISTOGRAM is
  deliberately NOT seeded (the absent-vs-zero rule is a rule about COUNTS; a
  seeded histogram over zero observations says what the seeded counter already
  says, at 21 lines per pair against 1). Buckets are
  `exponential_buckets(0.0005, 2.0, 18)` = 0.5 ms … 65.5 s, because the house 15
  tops out below `PERMIT_GUARD_TIMEOUT_SECS`, and timings are `Duration` rather
  than the pre-rounded milliseconds — every `queue_ms`/`exec_ms` this fleet has
  logged is `0`, so `as_millis()` would put 100% of observations in one bucket.
  `actor_id` stays a LOG FIELD and must NEVER become a label.
* **The RPC outcome classification**, derived per outcome from its enum's own
  docs: `unauthorized` and `replay` are FINDINGS, not declines — on a
  fleet-shared-key transport they mean clock skew, a half-rotated key, or a sender
  that should not be there (live count: 0 ever). `not_found` / `invalid` are
  DECLINED. `query_error` is a Finding on BOTH producers even though one is a
  caller error — a compromise stated rather than hidden, separated by `subject`.
  `write_ceiling` is a Finding because #760 already decided it that way.
* **ONE alert, `TalosRPCSubjectFailing`, warning; the refusal class gets none.**
  A ratio (>50% findings) with a `>=5` floor, sustained 10 minutes, and it cannot
  fire on an idle fleet (0/0 is NaN). `unauthorized` gets no alert of its own: zero
  observed, so any threshold is a guess and the obvious one fires on a rolling
  deploy's clock skew.
* **A THIRD metric family `talos_rpc_queue_duration_seconds` was declined**:
  backpressure is structurally unreachable at the measured volume (~0.9 calls/min
  against caps of 8/16/32, every observed `queue_ms` 0), the saturation signal
  survives as the `stale_deadline` outcome, and the split is unchanged in the log.
  Stated as a limit: queue-vs-exec attribution now lives in the log alone.
* The seven subject strings are DUPLICATED into `talos-metrics` rather than
  imported (importing would invert the layering) and pinned to their originals by
  a test — #760's `RPC_WRITE_CEILING_SUBJECTS` precedent.
* **The finalization ordering that makes a waterfall row start past the run's end
  is left alone** — it is a real ordering fact about the engine's failure path,
  not a rendering question. Population: 2 of 10,729 completed executions.

* **Neither Talos process exported a single `process_*` series (2026-09-11).**
  Measured while looking for a 26-hour RSS trend after #809: the controller's
  registry had 66 families and none about the process; every
  `process_resident_memory_bytes` in the dev Prometheus came from Prometheus,
  Grafana, Jaeger, Alertmanager and node-exporter. A controller leaking memory
  or file descriptors had NO series anywhere — `docker stats` was the only
  view (44 MiB / 9 MiB at the time, healthy). The prometheus crate's own
  `ProcessCollector` (`process` feature, procfs, Linux-only by its cfg) is now
  registered in `TalosMetrics::new` and in the worker's `init_telemetry` —
  before the exporter's `?`, for the reason the breaker seed sits there — so
  both `/metrics` carry RSS, virtual size, open/max fds, threads, CPU seconds
  and start time. **ONE alert, `TalosProcessFdsNearLimit`** (`open/max > 0.8`
  for 10 m, warning): the one process-level threshold that is not a guess,
  because the limit is read from the process. **Deliberately NO RSS alert** —
  `process_*` cannot see the cgroup limit, so a byte threshold pages at the
  wrong number on the next resize; and **NO `absent()` arm** — an image built
  before the collector exports nothing here, and a capacity alert firing on a
  rolling deploy's version skew is check 69's trap. Not a `TalosMetrics` field
  (check 58 audits fields for increment sites; a collector is sampled). Pinned
  by `process_metrics_are_exported_on_linux` in both crates, `cfg(linux)` so it
  is SKIPPED on macOS rather than green over a cfg'd-out body. **Measured and
  NOT changed on the same pass — outbound HTTP deadlines**: 24 `Client::builder()`
  statements in non-test code; a statement-aware scan finds 5 whose chain sets
  no total `.timeout(`, and every one is covered elsewhere — three are prose
  hits inside comments (`platform.rs`, `oauth`, `slack`; their real builders go
  through `build_outbound_webhook_client_with_timeout` / `build_integration_client`,
  both of which set one), the worker's per-execution client applies a
  per-request `.timeout(timeout_ms.min(120_000))`, and the local-LLM client is
  wrapped by `LOCAL_LLM_EXCHANGE_TIMEOUT_SECS`. Zero findings; recorded so the
  sweep is not redone.

* **Three security counters were dead for four months and a fourth surface's
  counter was never counting (2026-09-11).** Check 58's `BASELINE_DEAD` — the
  burn-down list its own doc says must shrink — had carried ten names since it
  landed. Measured against the live scrape: 15 registered families exported no
  series at boot; ten were the baseline. `talos_auth_2fa_attempts_total`,
  `talos_api_key_validations_total` and `talos_rate_limit_hits_total` are the
  three a security operator would reach for first (a 2FA brute-force burst, a
  key-guessing burst, a limiter refusing traffic) and every one read as
  NOTHING — not zero, absent. Now wired at the single recorder each surface
  already had (`record_2fa_success/failure`, every verdict in `validate_key`,
  the `Err(not_until)` arm of both middlewares plus the webhook per-trigger
  limiter), with label sets closed by the COMPILER
  (`talos_metrics::security::{TwoFactorOutcome, ApiKeyValidation,
  RateLimitKind}`) and every value pre-seeded — the born-at-one lesson from
  the same day, and for security counters the FIRST event is the one that
  matters. Four names were DELETED rather than wired: the two webhook series
  keyed on `trigger_id` (a per-row label) and the two cache series (three
  caches named in a comment, none wired). **No alert yet, deliberately**: a
  threshold on 2FA failures or key-guessing needs a baseline these series
  have never produced; the series come first. Guards: an exhaustive seed +
  recorder test in `talos-metrics`, a PRODUCTION-path DB test for every
  API-key verdict and the api-key limiter kind, and two source pins where the
  production path needs Redis or an axum `Next` to drive — stated as pins.
  `BASELINE_DEAD` went 3 → **0** the same day: the execution count/duration
  families are wired at every finalizer with the duration the finalizing
  UPDATE itself RETURNS (database clock, same row as the status write);
  `fail_execution_unless_terminal` turned out to be the one failure path that
  had never counted on `talos_workflow_executions_total` either.
  `trigger_type` was dropped from the module counter — it reads `webhook` on
  all 55 279 rows. **"Every finalizer" was wrong for the production module
  path, and the deploy said so within the hour**: the workflow side reconciled
  exactly (5 rows ↔ 5 counts ↔ 5 observations) while the module side read 14
  completed rows against a counter at 0. The engine finalizes a
  workflow-dispatched module row through `PostgresModuleExecutionStore::
  record_completed` in `talos-engine` — its own UPDATE, not
  `ModuleExecutionService` — and the DB test had driven the service. Wired
  the same way (RETURNING the duration; the status string mapped through
  `ModuleExecutionOutcome::from_status`, beside `as_str` which it inverts,
  an unknown spelling logged and NOT counted). The `cancelled` outcome
  had a second, wider hole: the sibling-cancellation UPDATE existed as SIX
  byte-identical copies (engine node hook, engine chain runner, both
  repositories, two scheduler paths) and none counted. ONE home now,
  `talos_workflow_repository::cancel_running_module_executions(pool, wf_exec,
  SiblingCancelReason)`, RETURNING each row's age and counting per row; the
  reason is an enum because it is the row's `error_message`. Enumerate
  finalizers by `grep "UPDATE module_executions"`, never by crate. Guards:
  the DB test drives the real store for all three engine statuses, a
  refused re-finalize (counts nothing), and the shared cancel fn against two
  siblings plus a control row; four mutations, four caught at the exact
  assertion (store record arm emptied; every status mapped to `completed`;
  cancel loop's record removed; loop truncated to one row — that last one
  is what "per row, not per call" buys); a compile-time source pin in the
  workflow repository reads the four former copy sites and fails if the
  literal returns. The archive's first M3 did not compile and was re-run —
  a mutation that does not build proves nothing.

**Measured and NOT changed.** `create_watch` accepted ANY `module_id` uuid with
no error and no trace — the most likely origin of this fleet's dangling channel —
and a correct create-time gate needed a THREE-valued module-visibility read that
did not exist (`get_module` folds "not found" and "DB error" into one `Err`;
`module_owned_by_user` has no `user_id IS NULL` arm). Closed later by
`talos_registry::module_visibility`. No MCP tool listed GCP watch channels, and
wiring one into the hygiene report would have inverted `talos-hygiene-service`'s
layering — closed later by the leaf crate `talos-push-channel-inventory`.

**Latent.** 1 of 1 module-binding channels on this fleet is dangling; the audit
table holds **zero** `gcp_%` rows, so the `recent_failure` enrichment has nothing
to show yet. `gcal`'s channel count is ZERO and it is enrolled anyway — a survey
that silently covers two of three is the misleading-report class one level up.

**Populations, so nobody re-measures.** The `tokio::spawn` inventory
(`scripts/background-task-inventory.py`, checked in): 54 controller sites (not
63 — the difference is comments plus five uses of `tokio::spawn` as a FUNCTION
VALUE), 45 loop-shaped, exactly 1 binding the handle; plus **127** further
library-crate sites in 34 crates. Of the 28 the 60-line window called loops,
**13 were false positives (46%)** once classified by reading them. The
`talos_rpc` inventory: **1590** production `mcp_error` call sites (883 `-32602`,
648 `-32000`), against shipped comments claiming 411/409 — the house call style
breaks the call across lines, so a single-line regex saw 46.6% and 63.3% of its
own populations; and `grep -rn "JsonRpcResponse {"` reports 398 where the real
struct-literal count is **31**. **A line grep over Rust is not a population.**

**Lints: none added, `--count` stays 88.**
* *"a long-lived `tokio::spawn` must go through `spawn_supervised`"*: cannot tell
  a loop from a one-shot textually; would ship at 28 markers on correct code and
  still miss a loop whose `loop {` sits past the window. The per-file
  `task_supervision_pin` count assertions are stronger and cost no check number.
* *"every `BackgroundTask` must be pre-seeded"*: not expressible — the enum and
  the seed list come from one macro table.
* *"a metric publish must have a test that moves the series"*: not expressible —
  the defect is that nothing REACHES an increment site that plainly exists, which
  needs a call graph. The cheap substitute ("does any file referencing the
  collector contain an assertion") was built and REJECTED: it answers yes for 28
  of 29 pre-seeded collectors, i.e. it only proves the file has tests somewhere.
* *"a watch create that accepts a caller-supplied `module_id` must consult the
  gate"* (BUILT as `scripts/lint-watch-module-binding-candidate.sh`, kept):
  **19 sites on main of which 3 are real — 15.8% precision** — and **10 on the
  fixed tree, every one legitimate**; worse, 3 of the 8 it calls gated are the
  `_locked` renewal helpers that must NOT be gated.
* *"every Prometheus label value must come from a closed compile-time set"*
  (BUILT as `scripts/lint-rpc-label-closure-candidate.sh`, kept): inspects 121
  `with_label_values` arguments and flags **73** as not provably closed, and
  essentially every one is correct — the same 73 on both trees, **0-for-0 as a
  bug detector**, 73 markers on correct code. It cannot be narrowed: no textual
  rule tells a `&'static str` whose value came from the caller from one whose
  value came from an enum a frame up.
* *"a `clamp` whose bounds are both computed must have its min <= max proved"*: a
  dataflow question.

**The mutation that mattered.** 29 pre-seeded collectors exist and mutation-testing
all of them is ~80 build+test cycles, not attempted; of the 17
`talos_scheduler_dispatches_total` call sites, deleting each in turn found **SIX**
survivors (not the one previously recorded), now pinned by a per-outcome call-site
count with its own tripwire — 17 caught, 0 survivors on the re-run.

### A documented knob whose advertised range is inert → [`2026-09-09-a-documented-knob-whose-range-is-inert.md`](docs/engineering-log/2026-09-09-a-documented-knob-whose-range-is-inert.md)

**The class.** A HARDCODED constant binds before a documented tunable's
advertised range, so most of that range does nothing and no operator-facing
surface says so. `ADAPTIVE_RANK_LOOKBACK_DAYS` is documented in TWO places as a
training window clamped to `[1, 3650]` days; `TRAINING_FETCH_CAP = 20_000` binds
first, because the Phase-1 fetch is `ORDER BY created_at DESC LIMIT $cap`.
Measured on the reference fleet 2026-09-09: **the configured 30 days was a
fitted 6.555, and the fetched row set was byte-identical at 7, 30, 60, 90, 365
and 3650 — every value from 7 up, i.e. 99.8 % of the advertised range.** Through
the production fit the coefficients agree to SIX DECIMAL PLACES at 30/60/90. The
knob is effective DOWNWARD only. This is the model that decides which memories
reach `__actor_context__`, and its learned weights are live and materially
different from the global blend (recency 1.23 vs 0.30, importance 1.66 vs 0.50
normalised to relevance).

**The disclosure already existed and was in the WRONG UNIT — that is the defect.**
#654 shipped the truncation WARN, `FetchProvenance` on the stored model, and the
operator digest's `n_fetched` / `window_available` / `window_rows_dropped` /
`population_note`. All ROWS. And `n_available` is counted with the operator's own
`since`, so it MOVES when the inert knob is turned: raising 30 → 90 grows
`window_rows_dropped` from 52 642 to 90 805 while every coefficient stays
bit-identical. **The report does not merely fail to say the knob is inert; it
reacts to the inert knob in the direction that reads as "the change took
effect".** So `FetchProvenance` now also carries `configured_lookback_days` and
`oldest_fetched_age_days` — the latter free, since the fetch's rows are already
in memory and its LAST element is the oldest row read — and every surface reports
`effective_lookback_days` / `lookback_shortfall_days` / `lookback_inert` beside
the row counts.

**Decisions.**
* **The cap stays 20 000 and is deliberately NOT made tunable**, and COST IS NOT
  THE REASON — measured, the production fetch is ~18 ms at 20 000 rows and ~59 ms
  at 50 000, on a six-hourly tick over ≤50 actors. The reason is that **a cap knob
  would not restore the advertised range.** There are FOUR ceilings, not one:
  `TRAINING_FETCH_CAP` (6.6 days), `RANK_TRAINING_EXAMPLE_MAX = 50_000` (~17
  days), execution ARCHIVAL at `ARCHIVE_AFTER_DAYS` (~30 days), and provenance
  retention at 90. **The third binds even with NO cap**: past archival the
  fetch's `LEFT JOIN workflow_executions` finds nothing, so the row carries no
  outcome label and `build_training_set` drops it — measured, rows with a live
  execution SATURATE at 72 712 from 30 days on while the raw count climbs to
  110 812 at 60, and at an unbounded cap days=60 and days=90 fit the same model.
  Shipping a knob that still could not reach its documented range would be this
  same defect with an extra step.
* **Training on RECENT outcomes is now DECIDED rather than an accident of the
  `ORDER BY`** — and the load-bearing half is the LABEL HORIZON, not the cap: past
  ~30 days this corpus has no labels at all, so a recency-weighted fit is the only
  thing it can support. The cap chooses 6.5 over 30; archival chooses 30 over
  3650, and that half was never a choice anybody could have made differently.
* **`n_examples` keeps its meaning** ("usable labeled rows this fit consumed").
  #654 decided that; renaming it would break the stored artifact,
  `recent_rank_fits`' SQL and the digest's shape for no gain. What changed is that
  it can no longer be read alone.
* **Nothing alerts on the new series**, argued: on a fleet with one busy actor
  the cap binds every tick forever, so an alert would fire permanently and train
  operators to ignore it (check 69's trap). **The same argument applies to the
  LOG LEVEL, and was applied 2026-09-11**: the `rank_training_truncated` line
  was WARN at every tick and every boot — measured, the ONLY WARN a clean
  controller boot produced on each of the last eight deploys — and is now INFO
  with every disclosure field kept; the seeded counter pair and the shortfall
  gauge are the signal anything reactive should read. The population-count
  FAILURE beside it stays WARN: a read that did not answer is not a steady state. `talos_rank_training_fetches_total
  {coverage=complete|truncated}` is a closed compile-time PARTITION with **no
  `actor_id`** — caller-influenced, so it stays a log FIELD — both values
  pre-seeded. `talos_rank_training_lookback_shortfall_days` is the WORST case
  across a tick, because `actor_id` cannot be a label; **its zero is ambiguous
  ("no shortfall" vs "no tick yet") and the seeded counter pair is what resolves
  it**, which is stated in the gauge's own HELP text rather than left implicit.
* **`lookback_inert` needs a whole-DAY threshold**, not `> 0.0`: the configured
  window comes from the `since` the tick computed and the effective one from a
  clock read after the fetch returned, so a sub-day gap is measurement noise and
  a `> 0.0` test would report every unbound fetch as inert.
* **Unknown stays unknown.** A truncated fetch whose oldest row cannot be dated
  yields `None`, never the configured window; `lookback_inert` is FALSE on
  unknown, because it drives a sentence telling the operator their knob does
  nothing and asserting that from an unmeasured fit is the determinate negative
  this whole disclosure exists to remove.

**Is it a class? FOUR sites, TWO undisclosed — not 117 and not 1.** Measured by
enumerating every call site of every documented numeric `talos_config::` knob and
reading each: (A) this one; (B) `HISTORY_MAX_EXECUTIONS = 50` vs
`history_window_days()`; (C) `HISTORY_WINDOW_DAYS.min(archive_after_days())`;
(D) hardcoded candidate-row counts (`10`/`20`/`clamp(1,50)`) vs
`SMART_MEMORY_CONTEXT_BYTE_BUDGET`, which has no upper clamp — **D was
undisclosed anywhere; CLOSED 2026-09-11 by disclosure** at the knob's doc
comment and its `configuration-reference.md` row, with the measurement: every
production caller asks for 20 candidates, so the budget is inert above
`20 × per_memory_cap` = 60 000 (5× its default) and on the reference fleet's
busiest actor (9 memories) above 27 000 — BELOW that it binds, which is the
intended shape, so unlike A this knob's default sits inside its live range.** **B is the instructive
one**: its doc comment already says *"on a high-frequency one it covers roughly
the last twelve hours, so the check is strongly recency-biased there"* — the
sentence this package had to write for A. **The repo already knows how to write
this disclosure; it writes it where the reader of the CONSTANT will see it, and
not where the operator reading `docs/configuration-reference.md` will.** That
asymmetry is the generalizable finding, and it is why the interaction is now
documented at BOTH ends (the knob's own `talos_config` doc comment, both docs
files, AND the const). The contrast that proves the shape: `stale_sweep`'s
`STALE_SWEEP_BATCH = 500` beside `STALE_EXECUTION_MINUTES` is the same query
shape and is NOT a defect, because it orders `started_at ASC` and repeats, so the
backlog drains. **`DESC` + a cap + no cursor is what makes A one.**

**Measured and NOT changed.** The fitted weights on this fleet are UNCHANGED —
this package is disclosure only, and the refit delta is recorded so the trade is
on the record rather than taken: an unbounded 30-day fit moves relevance −11.2 %,
recency −10.1 %, importance −4.8 %, access +2.3 %, i.e. ~7 % harder on importance
normalised to relevance. #654 measured the downstream effect (top-1 injected
memory moved in 1.07 % of executions, a LOWER bound since the provenance table
sees only ALREADY-INJECTED memories) and **neither fit is known to be the better
one — there is no held-out evaluation of this ranker.** Two ADJACENT findings
verified and left alone, both "a documented knob that does nothing" in a
different shape: **`DB_EXECUTION_TIMEOUT_SECS` is fully inert** (two hits
workspace-wide, both in `talos-db/src/lib.rs`, and the value reaches only a
`tracing::info!` — it is applied to no pool) and **`EXECUTION_MAX_ROWS` has no
consumer at all** (referenced only by `talos-config`'s own tests). Each is a
behaviour change with its own blast radius. **CLOSED 2026-09-11 by DELETION,
which is not a behaviour change**: nothing read either value, so removing the
reads, the accessor, its three tests and the connect line's `execution_timeout=`
claim moves no runtime; both doc rows are struck through (`GRAPHQL_MAX_DEPTH`'s
precedent). Measured before deleting, so the population is known: of the **331**
documented tokens in `docs/configuration-reference.md`, exactly ONE has a
`talos-config` accessor with zero callers (`EXECUTION_MAX_ROWS`), and
`DB_EXECUTION_TIMEOUT_SECS` is the one read directly by a crate and applied to
nothing. Wiring either was declined: there is no "execution-path pool" for a
second timeout to govern (live `pg_stat_statements` max application statement:
274 ms), and count-based eviction would be a new destructive sweep beside the
age-based one that already exists. The same package fixed `set_workflow_priority`'s
success line, which still said "New executions will be dispatched with this
priority" after #801 had corrected the description.

**Lints: none added, `--count` stays 88.** Two candidates built and measured over
`controller/src`, `worker/src` and every `talos-*/src`. *"a ±5-line window
carrying both a `talos_config::` read and a bare SCREAMING_SNAKE const"* reports
**116 sites in 50 files**, nearly all env-var NAME STRINGS and `DEFAULT_*`
constants that ARE the knob's default — and, decisively, **it does not report
this package's own site at all**, because the knob is read 200 lines from where
the const is consumed. A detector green over the defect it was written for is the
gate-that-doesn't-gate shape (#624, checks 64/65). *"an explicit clamp of a
`talos_config::` value against a const"* reports **2 sites, 1 real** — 50 %
precision over a population of two, below #765's bar, and it structurally cannot
see A, B or D, which are argument-position rather than clamp-position. Deciding
which of two bounds binds FIRST needs the `ORDER BY`, whether the reader repeats
with a cursor, and the fleet's row rate; that is a judgement, not a grep.

**Guards, and what they do NOT cover.** `observe()` is protected STRUCTURALLY —
it is the tick's only source of the `FetchProvenance` that `fit_rank_weights`
REQUIRES (#654's rule), so deleting the coverage counter means deleting the fit.
`publish()` is an ordinary call site and is a **MEASURED SURVIVOR**: a tick that
computes every shortfall correctly and never publishes leaves the gauge at its
seed, compiles clean and looks like a healthy fleet. A `Drop`-based publish was
REJECTED — it would fire on the tick's early-`?` return and publish `0.0` for a
tick that measured nothing. What partially mitigates it is that the gauge and the
counter are documented as a PAIR, so `truncated` climbing beside a 0 shortfall is
self-contradictory. Two other survivors were found and CLOSED rather than
recorded: the digest READ (`recent_rank_fits` is a `sqlx::query_as` over a
runtime `&str`, so a projection that yields NULL is check 88's class — closed by
`controller/tests/rank_training_window_disclosure_tests`, CTRL_TESTS per 64b,
whose CONTROL is a pre-disclosure artifact that must still read as UNKNOWN), and
the digest RENDERER, which computed the whole disclosure and dropped it while
every test stayed green until `rank_fit_row` was extracted out of an `async`
method over four repositories — checks 74b/79b's stated limit, and extraction is
the only thing that closes it.

**The trailing-space item (#788's footer).** Seven lines in
`talos-mcp-handlers/src/executions.rs` ended `... the \n\`, so every wrapped line
of the waterfall's beyond-total footer carried a trailing blank. Fixed. **The
lint was measured and REJECTED**: #785's checker looks for runs of ≥5 spaces and
is structurally blind to a single one; extending its literal resolver to find a
rendered line ENDING in whitespace gives **13 hits / 5 files pre-fix (7 real) and
6 / 4 after** — 53.8 % precision, six markers on correct code (three trailing
spaces inside multi-line SQL raw strings, a regex character class `[^ \t\n]`, and
a deliberate whitespace fixture). **One measurement error worth carrying**: the
first detector used `[^\S\n]+\n`, which matches `\r\n` — `\r` is whitespace and
is not `\n` — and reported **82 hits across 23 files**, every HTTP and MIME
header among them.


### The database was the last unmeasured layer → [`2026-09-10-the-collection-nobody-read.md`](docs/engineering-log/2026-09-10-the-collection-nobody-read.md)

**The class.** A COLLECTION turned on with no READER. #786 added
`shared_preload_libraries=pg_stat_statements` and the guarded migration
`20260908120000_pg_stat_statements_when_preloaded.sql`, whose own header ends
*"Nothing in the application reads this extension."* Because that GUC is
POSTMASTER-level the preload took effect only at the **2026-09-10 02:14 UTC**
restart; from that minute every statement the platform issues has been timed by
the server and read by nothing. #786 gave MCP tools
`talos_mcp_tool_duration_seconds`, #787 the signed-RPC data plane
`talos_rpc_duration_seconds`, `get_fuel_usage_report` covers module fuel — SQL
had no equivalent, and it is where an N+1 or a missing index shows up.

**Worth building, and the evidence is not an argument.** The first fifteen
minutes of that window independently reproduced a documented N+1 with no code
read: `SELECT MAX(started_at) …`, the reliability ratio and
`UPDATE workflows SET readiness_score …` each at **36 calls**, which is the
workflow count, against a loop this file already records as "THREE queries per
workflow (108 for the 36-workflow fleet)".

**Every premise of the brief was REFUTED, and each refutation changed the
design.**
* **`talos_guest` has ZERO rows in the view, and not for want of sandbox
  traffic.** The `SET LOCAL ROLE` fence is gated on `TALOS_RPC_GUEST_ROLE`,
  which is UNSET here (`enforce_production_db_sandbox_posture` forces it only in
  production), so guest SQL runs as the APP USER and is **indistinguishable in
  this view from the controller's own statements**. "Exclude the sandbox role"
  would have been a control that does not exist.
* **`pg_stat_statements` NORMALISES CONSTANTS**, including literals embedded in
  the SQL text — measured: two statements differing only in a string literal
  collapse to ONE entry with `calls = 2`, and the sandbox CTE wrap normalises
  down to `note = $1 … LIMIT $3`. Jumbling replaces `Const` nodes and does not
  care how the constant reached the parser.
* **What it does NOT normalise is the risk**: IDENTIFIERS (above all column
  ALIASES — `SELECT $1 AS "<anything>"`), COMMENTS, and UTILITY statements
  (`track_utility` defaults ON). So query text here is, in the general case,
  **arbitrary caller-authorable bytes**.
* **Tenant data was already in it**, from a path with nothing to do with the
  sandbox: `SET LOCAL app.current_user_id = '<uuid>'`, because `SET LOCAL`
  cannot bind parameters and `TenantReadScope::set_local_user_sql` formats the
  UUID in — correct for injection safety, and it means every distinct acting
  user mints its own entry.
* **A state nobody had named: Postgres redacts the text itself.** A
  non-superuser without `pg_read_all_stats` reads the literal
  `<insufficient privilege>` in `query` (measured: **239 of 252** as
  `talos_app`), which the migration's own header calls the common managed-Postgres
  posture.
* **C2's literal grep claim was false too**: three `.rs`/`.sh` prose sites said
  "there is no `pg_stat_statements` on this stack", true on 2026-09-08 and false
  from the restart. Corrected in place rather than deleted — they are why the
  MCP instrument's statement counting is CLIENT-side, and that reason stands.

**Decisions.**
* **A read-only MCP tool `get_sql_statement_report`; NO metric, NO alert, NO
  Helm change, NO `pg_stat_statements_reset()`.** The metric rejection is NOT
  about cost — the view scans in **0.15–0.20 ms warm at 259 entries**, ~3–4 ms
  at the 5000 cap, which a 15 s scrape can afford. It is about the LABEL: the
  only actionable content is PER-STATEMENT, `query` is unbounded
  caller-authorable text (check 58's DoS rule, #787's closed-compile-time-set
  rule) and `queryid` is an unbounded int. Every aggregate that IS expressible
  is unactionable or duplicates the tool, nothing would alert on it
  (`dealloc`, the one real "the instrument stopped measuring" signal, is **0**
  here), and on most deployments it would be permanently 0 because the
  extension is absent by design — the absent-vs-zero defect this package
  removes.
* **PLATFORM-ADMIN ONLY, and a REFUSAL rather than a narrowed answer.**
  `pg_stat_statements` has NO tenancy dimension — `userid` is a Postgres ROLE,
  not a Talos user — so there is no correct per-tenant slice of the text OR of
  the aggregates: the entry COUNT alone discloses how many distinct users a
  deployment has. `handle_query_paginated` is the precedent, gated on the same
  flag for the same reason. A platform admin can already read every tenant row.
* **Text is SANITISED even for that admin**, and not for confidentiality: a
  `database`-world module must not be able to plant an ANSI escape, an RTL
  override or a forged line break in an operator's console. Deliberately NOT
  `talos_validation::reject_control_chars` — that REJECTS an input about to be
  stored, this SANITISES a value already on disk that cannot be rejected.
* **Availability is FIVE-valued**, and PRESENCE is read from `pg_extension`
  rather than by classifying a `42P01`, so "not installed" is a positive
  finding. `NotLoaded` (`55000`) was reproduced in a throwaway
  `pgvector/pgvector:pg17` container with no preload (`CREATE EXTENSION`
  SUCCEEDS; the first read raises) — not read out of a header.
* **`entries_evicted: None` is not `0`.** `pg_stat_statements_info` is 1.9+ (PG
  14), so a server below that cannot say whether eviction happened. Reproduced
  rather than stubbed: PG 17 still ships the 1.8 script, so
  `CREATE EXTENSION … VERSION '1.8'` is a real pre-`_info` install and the DB
  test drives one. The reader names only the STABLE column subset for the same
  reason — `toplevel` is 1.9+ and the block-timing columns were RENAMED in 1.11.
* **`talos-statement-stats` is deliberately OUTSIDE check 88's PREPARE roots.**
  Every statement in it names a relation ABSENT BY DESIGN on most servers, so a
  gate whose premise is "this relation must exist" would go red on correct code.
  The guard is `controller/tests/statement_stats_tests` (CTRL_TESTS per 64b),
  which drives the real statements against a database WITH the view and one
  WITHOUT it.
* **`guest_role_for_query` becomes `pub` rather than being re-implemented.** A
  second reader of `TALOS_RPC_GUEST_ROLE` that skipped
  `is_valid_pg_role_identifier` would report a control as working when an
  invalid value has silently switched it off.

**Measured and NOT changed.**
* **`SET LOCAL app.current_user_id = '<uuid>'` stays as it is.** `SET LOCAL`
  cannot bind parameters; `SELECT set_config($1,$2,true)` would normalise, at
  the cost of changing the RLS scoping chokepoint (one simple-query round trip
  today, by design) — a behaviour change with fleet-wide blast radius, not a
  report fix. The consequence is recorded instead: on a multi-tenant deployment
  each distinct user mints its own entry against the shared 5000 cap.
* **`talos-db-monitor` (`QueryMonitor`, slow-query threshold, per-query
  metrics) still had ZERO callers** — `controller/src/bootstrap/services.rs`
  recorded it as one of four dead-binding scaffolds removed by MCP-704. The
  workspace already contained a statement-timing reader that had never recorded
  a statement; it was left alone then, and DELETED 2026-09-11 together with
  `talos-jobs` (see the whole-codebase review digest, package K).
* **Check 88 covered 77% of the population its name claims — CLOSED
  2026-09-11 by widening the roots to every crate's `src/`.** Its
  `SQL_PREPARE_ROOTS` was a HARDCODED crate list — check 74's glob and check
  64's runner list are the same rot mode. Counted over every non-test `.rs` on
  2026-09-10: **934 static sqlx statements INSIDE the roots, 274 OUTSIDE
  across 28 crates**, at least four of them repositories BY ROLE and not by
  name. Re-measured on 2026-09-11 with the probe itself (the authoritative
  count, not the grep): **949 inside, 1227 total over 140 crate roots, so 278
  newly covered** (`talos-ml` 85, `talos-oauth` 29, `controller` 24,
  `talos-engine` 20, `talos-webhooks` 19, `talos-scheduler` 18,
  `talos-workflow-versions` 17, `talos-api-keys` 16, `talos-system-repo` 15,
  `talos-totp-2fa` 12, `talos-google-cloud` 10 …). **Every one of the 278
  PREPARES — zero findings**, which is stated plainly rather than implied:
  this widening is a GATE improvement, not a bug fix, and the only thing it
  bought today is that the next renamed column in `talos-ml` or `talos-oauth`
  fails the lint instead of a request. Cost 0.6 → 0.9 s. The roots are now a
  glob over `controller`, `worker` and `talos-*`, so a crate that gains its
  first sqlx statement is covered the day it does; the zero-roots and
  zero-statements arms still FAIL rather than skip.
* **`talos_guest` is unreachable on this deployment and that is the DEFAULT**,
  not a local misconfiguration.
* **The first thing the new instrument measured was the repo's own lint, and
  that WAS changed.** Check 88 emits `PREPARE sN AS <sql>;` + `DEALLOCATE sN;`
  per statement — both UTILITY statements carrying a UNIQUE NAME, so neither
  normalises — which at its 951 statements is **~1900 `pg_stat_statements`
  entries per run against a default `max = 5000`, ~38% of the cap, every run.**
  Measured either side of one `TALOS_LINT_SQL_PREPARE=1 make lint`:
  `4640 → 4392` entries, `dealloc 0 → 1`, and **nine of the operator's real
  `talos` entries evicted**. Attribution stated precisely: the cap pressure was
  ~74% this session's own test clones, so on a clean instrument the lint alone
  (438 + 1900) would not have evicted — the CHURN is unconditional, the
  eviction was the combination. Fixed with one line,
  `SET pg_stat_statements.track_utility = off;` at the head of the psql script:
  re-measured, a full run now adds **2** entries (the two measuring queries),
  leaves `dealloc` unchanged and leaves ZERO `prepare s%` entries, and still
  reports `scanned 951 static statement(s) … ✓`. The refusal paths were
  REPRODUCED rather than assumed — `track_utility` is a `superuser`-context
  GUC, so a non-superuser role gets `42501` and a server without the extension
  `42704`; pointing the SET at a nonexistent GUC and re-running gives normal
  counts and exit 0, because psql runs `ON_ERROR_STOP=0` and the attribution
  loop ignores every `ERROR:` before the first `@@@` marker.
* **A side effect of this work, disclosed rather than left to be found.** An
  entry OUTLIVES the database that minted it, and the controller harness gives
  every test its own `CREATE DATABASE … TEMPLATE` clone. After this session's
  runs the live cluster held **3462 entries with 1538 headroom, 2552 of them
  (73.7%) from databases that no longer exist**. `dealloc` is still 0, so
  nothing real was evicted. `pg_stat_statements_reset()` was NOT called — shared
  operator state, and it would destroy the 421 real `talos` entries too. The
  measurement is why `coverage.entries_for_dropped_databases` exists in the
  report; it was added after it, not before.

**Latent on this fleet, stated plainly.** The one user on this deployment has
`is_platform_admin = false`, so the tool **refuses every caller here today**. It
joins ~14 existing tools in exactly that state (`query_paginated`,
`pause_executions`, `set_wasm_config`, `get_secret_access_log`,
`set_archive_policy`, …), all gated on the same column; enabling it is one
operator `UPDATE`. And the collection window is only as old as the last
Postgres restart, which is why `window_is_since_server_start` is a field.

**Lints: none added, `--count` stays 88.** Every candidate, measured:
* *"a file naming `pg_stat_statements` must name the availability
  classification"* — population **4 files**: the crate, its DB test, the handler
  (which names it) and one prose-only test header. ONE production site, below
  #765's bar; the structural answer is stronger — `StatementStatsRead` is
  `#[must_use]` with no `Into<Option>`, no `.ok()` and no `is_available()`
  boolean, so the collapse the check would look for does not compile into a
  one-liner.
* *"a report reading an OPTIONAL relation must classify availability"* —
  population **2 files**, one a test.
* *"a caller-authorable string reaching a report must be sanitised"* — the
  workspace already holds **30** `sanitize_*` functions, every one correct, and
  "is this string caller-authorable?" is a dataflow question. Zero-for-zero as a
  bug detector.

**Mutations: 14 applied worst-first, 14 caught — one of them only after it
SURVIVED, and one only after the stub it was measured against was made
faithful.** M1 (absent extension → an empty `Available` report) fails loudly;
so do the gate deletion, the gate failing OPEN, the bypassed sanitiser,
Postgres' redaction marker rendered as a statement, the dropped `dbid` filter,
a silently-defaulted `order_by`, `truncated` pinned false, the withheld-text
count, and the dropped-database count.
**M12 was a real SURVIVOR**: `classify_view_error`'s SQLSTATE arms are the ONE
place a deployment fact is asserted from an error and nothing drove them — the
DB suite runs on a cluster that HAS the preload, so it cannot produce `55000`,
and the unit tests built `NotLoaded` directly. `55000 => NotInstalled` ("you
never installed this", to a server that only needs a restart) passed
everything. Closed with a test-only `sqlx::error::DatabaseError` stub, because
`PgDatabaseError` has no public constructor.
**M14 was a NO-OP before it was a catch**, and that is the sharper lesson: a
message-based shortcut ahead of the SQLSTATE match never fired, because the
stub's `Display` did not render its MESSAGE the way a real `PgDatabaseError`
does. **A stub that does not render like the thing it stands in for makes every
assertion against it prove less than it appears to.**
**M7's first form was a correct non-survivor**: it mutated the `Ok(None)` arm
of the `_info` read, which is essentially unreachable because the view returns
exactly one row whenever it exists — the REACHABLE unknown path is the
`Err(42P01)` arm, and that one is caught.
**And the harness itself produced a FALSE result before it was fixed**:
`shutil.copy` does not preserve mtime, so a reverted file came back OLDER than
the mutated build's fingerprint and cargo reused the MUTATED artifact — one
mutation's failures reappeared verbatim under the next one's run. The rule
"print the diff and confirm the mutation landed" needs a second clause —
confirm the REVERT landed too — and a baseline probe that must be green now
runs first every time.

**Stated limits.** The `NotLoaded` and `denied` / `view_missing` arms are
covered by UNIT test on the SQLSTATE, not by the DB suite: producing `55000`
needs a postmaster without the preload, which this cluster is not. The tool was
never called through a deployed controller (the running image predates it), so
the live read after deploy is the honest guard for the wiring — the position
#767, #769 and #771 each took about their own changes. And the reader's own
statements appear in its own report, which is honest but can surprise.

### A per-call timeout spent on somebody else's inference → [`2026-09-09-the-timeout-that-was-not-per-call.md`](docs/engineering-log/2026-09-09-the-timeout-that-was-not-per-call.md)

**The class, and it is a new one for this series: a resource bound whose
denominator is not what its name says.** `LOCAL_LLM_EXCHANGE_TIMEOUT_SECS` (60 s)
is documented as bounding **one call** — *"a cold-start with a 7B+ model can take
20–40 s while the model loads into VRAM. 60 s gives headroom without masking an
actually-stuck call."* Nothing made that true. Talos issued an unbounded number of
simultaneous `/api/chat` requests to a backend that serves them **one at a time**,
so the 60 s was **shared across every request in flight**. Reconstructed to the
second on 2026-09-09: the second of two calls fired 1.2 s apart spent its ENTIRE
60 s budget queued and timed out having been sent nothing to wait for.

**Where the serialization actually is: NOT in Talos.** `OLLAMA_NUM_PARALLEL:1` on a
NATIVE host Ollama 0.31.2 that this repo does not ship, does not configure and
cannot read. **And the `talos-ollama` CONTAINER is not that Ollama** — it publishes
no ports and serves `EMBEDDING_API_URL` only (3 810 `/v1/embeddings`, **0
`/api/chat`** across every log line `docker logs` will surrender). Anyone debugging
this from the container's logs sees an idle Ollama and concludes there is no herd.
Both the worker and the controller carry `OLLAMA_URL=http://host.docker.internal:11434`.

**The dose-response curve is the finding**, and the eleven-call anecdote that
motivated the package badly undersold it. All 1 194 completed LLM module executions
over 31 days, bucketed by concurrent LLM siblings: **0 → p50 8.5 s, 1.3 % over
60 s; 1 → p50 37.8 s, 20 %; 2 → p50 83.3 s, 58 %; 3 → p50 1106 s, 86 %.** The
consequence that decides the fix: **serializing is FASTER in aggregate, not merely
fairer** — two calls whose solo p50 is 8.5 s finish in ~17 s back to back against a
measured 37.8 s when they run together. Concurrency on a compute-saturated
inference backend is pure overhead.

**The fix is `talos-worker-runtime/src/host/llm_gate.rs`**, applied at both gated
sites (`complete*` and `complete-with-tools`) **BEFORE** the exchange timeout
starts, so queue time is not charged to a budget that measures one call's own
service time. Cap `TALOS_LOCAL_LLM_MAX_IN_FLIGHT`, default **1**.

**Decisions, so they are not re-litigated.**
* **The gate QUEUES and has no error variant.** It cannot refuse, by construction —
  the in-house precedent is every signed-RPC subject's `acquire_owned().await`, not
  one of which has a `try_acquire`. On wait expiry
  (`LOCAL_LLM_QUEUE_WAIT_SECS = 120`, deliberately equal to the job timeout so the
  gate never decides a job's fate) the call **proceeds UNGATED**, i.e. degrades to
  the pre-gate behaviour. That is what makes it a Pareto change: **there is no input
  for which it turns a call that would have succeeded into one that is declined.**
* **JITTER was measured and NOT shipped.** 116 of the 165 overlapping executions are
  OUTSIDE the 12:00–12:14 UTC window and the busiest single minute is **10:00 UTC
  (36 overlapping) — more than 12:00 (34)**, so there are at least two herds and 12
  LLM-bearing schedules, several colliding by construction (`35 7` vs `37 7`;
  `20 7-23/2` vs `25 7-23/2`). Jitter reaches ~30 % of the population, changes WHEN
  a user's workflows run, and opt-in-default-off fixes nothing on the fleet that has
  the problem. **Both would be better than either**; jitter is out of scope for a
  package that does not touch the user's schedules, not ruled out.
* **RAISING the timeout was DECLINED**, and the reason is epistemic rather than
  cautious: it helps only if the killed calls' true service time is under the new
  value, and every one of the 48 was aborted at 60 s, so that quantity is
  unmeasurable from outside. The gate's benefit is structural instead — queue time
  is not the call's fault.
* **Deliberately NOT gated**: `llm_streaming.rs` (a permit held for the life of an
  SSE stream deadlocks the two gated paths behind it); EXTERNAL providers (they
  serve in parallel and bill per token — serializing is a latency regression for
  nothing); and the CONTROLLER's `talos_llm::OllamaClient` (different process; this
  package's evidence is about the worker).
* **No alert** on `wasm_llm_gate_total{outcome}` (3 values, all PRE-SEEDED at 0) or
  `wasm_llm_queue_wait_ms`: `acquired` climbing is the gate working, `disabled` is a
  steady state an operator chose, and `wait_expired` degrades rather than breaks —
  an alert on a control working as designed is check 69's trap. The wait histogram
  records **every** local call including zero-waits, so its `_count` is the local
  call count and a ratio can be formed.
* **The cap cannot be right for every backend and the knob says so.** Talos cannot
  read `OLLAMA_NUM_PARALLEL`; on a GPU host serving 4 in parallel a cap of 1
  serializes work that could have overlapped. Default 1 matches the single-slot
  Ollama the bundled compose file provides. An unparseable value falls back to the
  DEFAULT, never to 0 — a typo must not silently switch a control off.

**Measured and NOT changed.** `wasm_llm_duration_ms` now INCLUDES gate wait
(`llm_start` predates the acquire) — the honest number from the guest's point of
view, with `wasm_llm_queue_wait_ms` separating the two; stated because it is a
meaning change to an existing series. The **attempt-window clamp is not the harm
vector**, checked over every node of every non-archived workflow: 11 nodes in 3
workflows, the already-documented population, none LLM-bearing, neither herd
workflow present. Three of the brief's five named workflows have **no LLM node at
all**.

**NOT latent — live, daily, and it has already failed a workflow.** 48 sixty-second
timeouts over 31 days (0.146 % of 32 972 `/api/chat`), **21 of them at exactly
12:01 UTC** and 24 in the twelve minutes after 12:00. the hourly alert-triage workflow failed outright on 2026-08-27 with `workflow execution timed out after 300 seconds` in a
window carrying six of them, and `pa-chief-of-staff` spent **174.5 s of its 180 s
budget** on 2026-09-07 — 97 %, of which 120 s was two timeouts that bought nothing.

**Guards, and what they do NOT cover.** Seven unit cases over the gate's own
semaphore (each with a control proving a wider cap really does overlap) plus
**three PRODUCTION-path cases** driving `wit_llm::Host::complete` and
`wit_llm_tools::Host::complete_with_tools` against the mock provider, reading peak
concurrency out of the **BACKEND** — with a raw-request control proving the mock and
the runtime can serve two at once, without which "peak == 1" proves nothing. **Nine
mutations, worst blast radius first; M8 was a SURVIVOR** — reverting the SECOND call
site left all 651 crate tests green, because a guard at the primitive cannot see a
call site (checks 74b/79b) — and it is now closed, so 9 of 9 are caught. **A
correction to this package's own first draft, measured rather than assumed:
`#[must_use]` on `LocalLlmSlot` does NOT protect the call sites** — both bind
`Option<LocalLlmSlot>`, the attribute does not propagate through `Option`, and a
probe reducing a site to a bare expression statement produced no clippy diagnostic
under `-D warnings`; the doc comment now says so rather than claiming a guard it
does not give. **No test drives worker → real Ollama**; the honest guard for the
live path is the read after deploy. The gate is **per-PROCESS**, so the fleet
ceiling is `WORKER_REPLICAS x cap`.

**Lint: BUILT, MEASURED, REJECTED. `--count` stays 88.** *A file applying
`LOCAL_LLM_EXCHANGE_TIMEOUT_SECS` must name `llm_gate`* reports **2 on a real
`git worktree` of pristine `origin/main`, both real, and 0 on the fixed tree** —
100 % precision over a population of TWO, which is the bar #765's own numbers
rejected. Decisively it is FILE-scoped, so it would be satisfied by a file naming
`llm_gate` in a comment while its call site discards the permit — **green over
exactly the two quiet mutations (M2, M8) this package exists to prevent**, the
gate-that-doesn't-gate shape (#624, checks 64/65). The second candidate — *a
`tokio::time::timeout` over a local-LLM exchange must be preceded by an acquire* —
is a dataflow question, not a textual one.

### The whole-codebase review → [`2026-09-10-whole-codebase-review.md`](docs/engineering-log/2026-09-10-whole-codebase-review.md)

**The class.** Fourteen parallel domain reviews over the entire workspace at `aeaf3956`, every High re-verified against the cited lines before a fix was written. The findings clustered into the classes this file already names, at sites the per-class sweeps had not reached: an unscoped read one crate away from a scoped twin (module export / `list_templates` / `tools/list`), a key inserted-or-inherited where its siblings are set-or-REMOVE (`__actor_context__`, `__staleness__`), a control that lived on the reqwest path and not the `wasi:sockets` path (`egress_scope`), a lint whose haystack had gone to zero (check 25), a cache keyed on the caller's literal (worker idempotency), and a controller that trusted the worker's gate on a fleet-shared key (the unsigned `max_fuel`, the cached `Failed` result).

**Decisions.**
* **`JobRequest.max_fuel` is HMAC/Ed25519-bound via `:fuel=`**, conditional-append at the END. Unlike `:attempt=`, non-zero fuel is the COMMON case, so **controller and worker roll TOGETHER** — a mixed pair fails closed on every fuel-carrying dispatch. The worker also clamps to `TALOS_WORKER_MAX_JOB_FUEL` (default `MAX_JOB_FUEL` = 50 000 000, pinned equal to `DEFAULT_MAX_FUEL_PER_NODE`).
* **The worker caches only `is_terminal_success()` results** (one predicate in the protocol crate, shared with the dispatcher's `is_success`); a hit with `dispatch_attempt > 0` and a non-success body is a MISS. Pipeline results are not success-gated (no app-level retry on that path). The `job_idempotency` header's premise "the dispatcher does NOT retry on timeout — only on a transport error" was false and is rewritten.
* **`(None, Some(wire))` in `pick_trusted_reply_topic` now returns `None`.** The live webhook path was the last request/reply dispatcher relying on the unsigned NATS reply header; it now allocates and signs its inbox. The remaining `reply_topic: None` senders are fire-and-forget and read `talos.results.<job_id>`.
* **`validate_worker_id` runs at result VERIFY, not only at sign** (`check_payload_shape` hook on both leaf verifiers); no wire change. The `worker_id`/`:llm_usage:` boundary collision is closed by refusal.
* **The dispatcher checks the reply's `job_id` before verifying its signature**, so a stray result never enters the nonce cache.
* **Engine is the reserved-key chokepoint**: `strip_engine_authored_keys` moved to `talos-workflow-engine-core::reserved_keys` (actor-memory-service re-exports), applied at both trigger seeds and the child seed; `__accumulated__`/`__actor_context__`/`__staleness__`/`__trigger_input__` are set-or-REMOVE in `merged`; committed module output is stripped of engine-authored INPUT keys (output-side protocol keys kept, pinned by test).
* **A dispatch-time capability-world ceiling** (`capability_ceiling::refuse_module_over_ceiling`, both single and pipeline paths) closes the child-workflow bypass; `apply_actor_to_engine` takes `user_id` and stamps four axes. `authorize_workflow_trigger` descends ONE level (capped 64); deeper children are the engine gate's job.
* **`sanitize_node_output` walks back to a char boundary; the per-field cap is 64 KiB** (was 10 KiB, which cut rendered HTML briefings mid-tag; the per-node 5 MiB cap is the memory bound).
* **Wait/ConfidenceGate drain in-flight siblings before pausing**; graph load REFUSES above the node cap (was a silent truncation + a panic at exactly the cap); `validate_workflow` reports `sub-workflow-cycle`.
* **`retry_condition` evaluation failure is "do not retry"**, matching the skip-condition gate.
* **Worker idempotency store is keyed `{user}:{actor|-}:{host}:{key}` and carries a request hash**; a reused key with a different request is REFUSED (`idempotency-key-reuse`), not served. `fetch_all` is capped against the remaining call budget up front, breaker per BATCH per HOST. Denials are ledgered up to 200/execution then one `_suppressed` row. SSE reader tasks are aborted with the registry; idle timeout 900 s (`TALOS_SSE_IDLE_TIMEOUT_SECS`). `webhook::send` honours `allowed_methods`, the per-host limit and the breaker. `.no_proxy()` on every worker client. `socket_grant` honours `egress_scope`.
* **`DISALLOWED_SQL_FUNCTIONS` absorbs the SQL/XML SPI family** (`query_to_xml`…, `xmltable`); the worker list is a PIN on it, not a supplement.
* **Sandbox/scratch/test_module run at `Tier1 + egress=Public`** when no actor is bound (private ranges denied, external LLM denied); a bound actor's `local` scope is honoured as deny-all `allowed_hosts`. `run_scratch_session` is Tier-1/ReadOnly with the real `user_id` and the role gate.
* **`clone_actor` copies `max_llm_tier`/`egress_scope`/`max_write_ceiling`** on both MCP and GraphQL.
* **GraphQL org mutations + `disableTwoFactor`/`logoutAllSessions`/`unlinkOauthAccount` require `Admin` scope**; org queries require `WorkflowsRead`; `disableTwoFactor(code)` is REQUIRED for API-key callers (optional in SDL so the SPA's argless mutation keeps working). **Check 22 now FAILS on a zero-gate mutations file.**
* **The WS lane rejects non-subscription operations and scrubs every streamed response** through the same scrubber as `graphql_handler`.
* **`list_template_metadata_for_user`** is what `list_templates`, `tools/list` and `get_platform_info` read: scoped, no `wasm_bytes`/`source_code`. `get_module_export_metadata` and `modules_accessible_by_user` are scoped; `add_node_to_workflow`, `add_error_handler`, `import_workflow`, `create_webhook` refuse a module the caller cannot see (uniform sentence). `security_audit` is platform-admin; `get_platform_info.fleet` is withheld (`null` + note) for non-admins. Role RBAC gate is one helper applied to all six compile/execute paths; caller `allowed_secrets` may only NARROW a template's.
* **Webhook dedup fingerprint is the VERIFIED format's own signature** (or `sha256(body)`), never a caller-chosen header. DLQ rows carry `__talos_dlq_authenticated`; replay refuses unauthenticated rows — **and both live enqueue sites are pre-auth, so every existing DLQ row is now un-replayable**; a post-auth enqueue site is the recorded follow-up. The IP circuit breaker counts AUTH failures only.
* **`tower_governor` keys on `extract_client_ip`** (`TrustedProxyClientIpKeyExtractor`), not the socket peer. Cookie-authenticated REST mutations carry `rest_cookie_csrf_gate`. `/health` caches 2 s and PINGs through one `ConnectionManager`.
* **`rotate_master_key` refuses unless the active KEK provider is `env`** (Vault rotation is Vault's); success writes `MASTER_KEY_ROTATED` to `secret_audit_log`. **`VAULT_ADDR` must be https in production** (`tls-prod-gate-vault`, escape `TALOS_ALLOW_PLAINTEXT_VAULT=1`); check 44 covers it.
* **`redact_json` is key-aware** under credential-shaped keys (suffix-anchored `is_credential_key`, deliberately NOT `talos_dlp::is_sensitive_key`, whose substring match would redact `primary_key`/`next_page_token` in stored node output).
* **`<agent_memory>` is no longer "authoritative"**: the directive calls memory the actor's own notes that may contain third-party text, closing tags are neutralised at every wrap site (`talos_memory::spotlight`, pinned against the template copy), and `persist_memory_*` REJECTS a key/value containing a closing delimiter. **`consolidated` is in `SYNTHETIC_MEMORY_KINDS`** (also stops auto-extraction of consolidated rows — stated trade-off). Consolidation/reflection/extraction prompts carry the directive + `<untrusted_data>`. Reflection entity upserts are SKIPPED until a provenance signal exists (Phase-4 synthesis effectively off).
* **Neo4j: constraints derived from all ten `ALLOWED_NODE_LABELS`**, fulltext over all ten (recreated only when the label set differs); every seed lookup is label-scoped; MCP graph calls under an 8 s timeout; entity names capped at 256.
* **Host-fallback compilation runs under `env_clear()` + allowlist**; `env!`/`option_env!`/`include_*!`/`#[path` are forbidden patterns; `--pids-limit 512`; lockfile/audit arms propagate the container-required refusal; `analyze_code` routes through `build_command`.
* **Chart**: backup CronJob runs under `bash` (dash has no `pipefail` — zero backups had ever run on in-cluster Postgres); `location /auth/oauth/` + `= /auth/csrf` (the `/auth/` prefix swallowed the SPA's OAuth callback); `frontend/nginx.conf` at parity and check 2 scans both; `/approvals/` was proxied by NEITHER and is now in both; COOP `same-origin-allow-popups`; NATS cluster route gets `authorization` + mTLS when `replicaCount > 1` and only `component=nats` reaches 6222; `DB_MAX_CONNECTIONS` 20 (2×20 of 60); `CryptoInvariantGauge` hourly; `TALOS_SIGSTORE_REQUIRED` renders `disabled` when empty; install.sh mints `PROMETHEUS_SCRAPE_TOKEN` and the NATS cluster pair; phase-1 `ollama.enabled: false` and the chart `fail`s on enabled-without-workload; `RUST_LOG` info; `docker-compose.prod.yml` is buildable at `RUST_ENV=staging` (plaintext URLs cannot boot `production`); `template-publish.yml` cosign-verifies the builder by digest and checksums oras.
* **Lints extended, `--count` stays 88**: check 25 derives `_scoped` twins (33) and fails at zero; 22 fails on a zero-gate file; 44 covers vault; 80 flags stock `postgres:`; 2 folds multi-line routes and scans both nginx files.
* **Migrations** `20260910120000` (archive `replayed_from_id`, in-flight `(workflow_id)`, `(actor_id, started_at)`, two DEK key-id indexes) and `20260910130000` (archive `actor_id` — the lifetime budget now counts live + archive).

* **Encryption tenancy, package C (2026-09-10, follow-up PR).** The three writers still encrypting org-scoped data under the GLOBAL DEK (`workflow_executions.output_data_enc` from the workflow- and actor-repository paths; `webhook_triggers.signing_secret_enc` from MCP `create_webhook`) now take the v4-or-global / v4-for-user path with the RETURNED format bound. **TOTP secrets and OTLP auth headers had an IDENTICAL AEAD context** (both `encrypt_value_aad_v4_for_user(_, user_id, user_id.as_bytes())`, so both columns derived one subkey and a blob from either column decrypted as the other — stopped only by the JSON parse); new writes use domain-tagged AAD (`talos_secrets_manager::aad::{TOTP_SECRET_TAG, OTLP_AUTH_HEADERS_TAG}`, `aad_for`), readers try the tag first and fall back to the bare id ONLY on `Aead` failure (`decrypt_versioned_tagged` → `AadPath`), re-encrypting lazily on the next write — no sweep, so a pre-tag blob stays swappable until the user re-enrols / re-saves (pinned as a limit). **Rollback caveat: roll controllers forward together** — an older controller cannot open a tagged TOTP/OTLP blob; a rollback after users re-enrol 2FA locks them out of TOTP (backup codes unaffected). MCP `create_webhook` now FAILS CLOSED when the owner has no personal org (parity with GraphQL). `re_encrypt_secrets` keeps v3 by construction (its SELECT excludes `format = 4`). The bare shared-foreign-id AAD shape existed at exactly those two sites; every other writer binds a row id.

* **The worker's own NATS credential, package F (2026-09-10, follow-up PR).** The review's G4c skipped it because "the worker's publish set is not confidently enumerable" — true, and the reason it is a DENY-list: the `messaging` WIT lets a guest publish to any non-reserved subject (the catalog's `message-publisher` takes its topic from config), and a publish permission violation is an ASYNC `-ERR` the publisher never sees, so an allow-list would have turned every guest publish to an unlisted subject into a silent drop reported as success. The SUBSCRIBE set IS closed and is the win: `talos.jobs(.>)`, `talos.pipeline.jobs(.>)`, `talos.workers.cmd.cancel`, `talos.approvals.wait.>`, `_WINBOX.>` — every controller reply inbox, every other worker's result, every `wasm.log.*` line, the heartbeat stream and the token streams are refused at the broker, which is the property signing cannot give. The worker connection gets its OWN inbox prefix (`_WINBOX`, `ConnectOptions::custom_inbox_prefix`; the controller keeps `_INBOX`) — that is what lets the allow-list admit the worker's replies without the controller's; a controller credential ever given a permissions block must allow publish on `_WINBOX.>`. ONE home for both sets: `talos_workflow_job_protocol::nats_permissions`, which RENDERS the nats-server fragment; the two checked-in copies (`deploy/nats/worker-permissions.conf` for compose, `deploy/helm/talos/files/nats-worker-permissions.conf` for the chart — Helm's `.Files.Get` cannot read outside the chart and compose cannot read inside it) are byte-pinned to the render (`TALOS_NATS_PERMISSIONS_WRITE=1` regenerates), the seven RPC subjects are cross-pinned from `talos-memory` (their consts live above the protocol crate), and `_WINBOX.` joined the guest `RESERVED_PUBLISH_PREFIXES`. The worker connection installs an **event callback** so the broker's `-ERR Permissions Violation` lines become WARNs (`target: "talos_nats"`) — without it a credential/code drift is a silent drop. **Proved on a live broker, not rendered**: `talos-workflow-engine-nats/tests/nats_worker_permissions.rs` runs the compose `nats.conf` in `make test-integration` (a second, permissioned NATS container) and asserts the broker agrees with `worker_may_publish`/`worker_may_subscribe` on 29 concrete subjects, each probe with a CONTROL on the unrestricted credential, plus both request/reply shapes; **the test was wrong three times before the model was right once** — the three tests share `talos.jobs` on one broker (serialized by a lock); `Client::flush()` is NOT a server round trip (the trace showed the worker's `SUB` arriving before the controller's `PUB` and the fan-out still missing it; a request/reply on the subscribing connection is the real barrier); and the barrier's own responder raced its first cross-connection request (1 in 8) until it proved its `SUB` with a same-connection round trip. The only ordering NATS gives you is within one connection. Deploy: install.sh mints + back-fills `NATS_WORKER_USER/PASSWORD`, `make up` back-fills `.env`, and the NATS StatefulSet mounts them as REQUIRED keys (an unresolved `$NATS_WORKER_USER` is a nats-server parse failure), so External-Secrets operators add them BEFORE upgrading — stated in values.yaml. Rolling is safe in both orders: an old worker keeps the unrestricted controller pair; a new worker against an old single-user config fails auth loudly. **Stated limits**: the prefix is per process KIND — every worker shares `_WINBOX.>`, so a compromised worker still reads a sibling's RPC replies (per-worker isolation needs NATS accounts / auth callout, which a static config cannot mint); `talos.jobs` is visible to every worker BY DESIGN, so the `encrypted_secrets` envelope under the fleet-shared WSK is readable fleet-wide — that control is `TALOS_ENVELOPE_SEALING=required`, not permissions; `talos.llm.stream.>` is DENIED because no worker publisher exists (measured), so a future producer must remove the deny entry and the pin says so. Inventory facts found on the way and recorded in `docs/nats-subjects.md` rather than fixed: `talos.workers.cmd.cancel` was missing from the table while inert `shutdown` was listed as live; `<prefix>.jobs.priority` has NO subscriber; the engine's `WORKFLOW_NATS_PREFIX` defaults to `workflow` and every deployment overrides it to `talos`.

* **`set_workflow_priority` promised dispatch ordering that nothing implements, and recorded its label on one trigger path of three (2026-09-10, follow-up PR).** The tool wrote a top-level `priority` key onto the graph and its description said the value was "stored on execution records for visibility and dispatch ordering". Measured: the ENGINE stamps `priority: 100` on every `JobRequest` at both dispatch sites, the dispatcher's `.priority` NATS subject (≥200) is reachable only from a library caller's builder and has no subscriber, and the worker has no priority handling — so there is no ordering, on any path. And the RECORD was wrong on most paths: of the NINE call sites that insert a `workflow_executions` row, three parsed the graph key inline (manual trigger, `test_workflow`, `test_workflow_draft`), five passed `None` and recorded `normal` whatever the workflow declared (the scheduler, the webhook router, `call_workflow`, `bulk_trigger_workflow`, `enqueue_workflow`), the GraphQL `testWorkflow` row omitted the column entirely (same result), and the column has no CHECK constraint; all 12,275 rows on the reference fleet read `normal`, so this was latent. The vocabulary now has ONE home, `talos_workflow_repository::ExecutionPriority` (`High`/`Normal`/`Low`, `as_str`, exact-spelling `parse`, `declared_in_graph[_json]` defaulting to `Normal`), and the five repository creators (four in the workflow repository, the GraphQL test row in the execution repository) take the ENUM rather than `Option<&str>` — a new caller cannot pass `None`; it derives the value from the graph it already holds or writes `Normal` and means it. The tool's description now says it is a LABEL and that nothing runs sooner because of it. **Deliberately NOT done: making the ordering real.** Mapping `high` → 200 would route those jobs to a NEW subject during a rolling deploy (new controller + old worker = every high-priority workflow fails with "no responders" until workers roll), and behind the worker's 100-permit semaphore a biased select would order almost nothing; that is a product decision with fleet-wide blast radius, not a report fix. Found on the way and DELETED: `ExecutionRepository::create_test_execution` had zero callers and bound an `Option<i32>` to the `text` column — check 88's PREPARE proves a statement plans, never that its bind TYPES match (the same limit the tag-cap finding recorded).

* **The installer applies RFC 0010 worker trust by default, in four loss-free phases (2026-09-11, follow-up PR).** The review's G4(c) left "consider defaulting ed25519 + sealing in the chart" as a suggestion; the chart shipped both as a commented-out runbook while the dev stack had run the full posture since 2026-07-06, so every installer-built cluster kept the one-fleet-key posture the review flagged (a compromised worker forges dispatches to peers and decrypts every job's secrets). **Why not one upgrade**: a worker signs RESULTS with Ed25519 the moment it holds a key and the controller verifies those only with the worker's public key; a worker verifies Ed25519 DISPATCH only with the controller's public key; a `required` worker refuses an unsealed secret-carrying dispatch — and Helm rolls both Deployments together, so each "before" is its own upgrade. `deploy/k3s/lib/worker-trust.sh` (pure bash, sourced by install.sh, tested in CI) encodes A (controller learns the fleet worker key) → B (workers get identity + controller key) → C (controller signs + seals) → D (both sides require). `auto`: fresh install → D; existing cluster advances ONE phase per run, recorded in `/etc/talos/worker-trust.phase` only after `helm upgrade --wait` succeeded; `hold`/`off`/`A..D` pin. Keys are minted with OpenSSL — the PKCS#8/SPKI derivation was checked against RFC 8032 vector 1 AND against the controller's own keygen on OpenSSL 3 (identical public key) — and stored in the bootstrap Secret with the worker seed STAGED under a key the chart does not mount until B. **Stated limits**: a single FLEET identity (every replica shares one worker key; per-worker keys go via self-registration, not automated here); macOS LibreSSL cannot run the derivation test (it skips loudly; CI runs it); nothing here changes the chart's bare-helm defaults, whose runbook is now stated to be the same sequence.

* **Package K (2026-09-11, follow-up PR): a fleet-posture bit that was an unset flag, and two crates nobody called.** `worker_identities.supports_sealing` — rendered by `get_platform_info.fleet` and the `register-worker-identity` CLI — came from an UNDOCUMENTED opt-in env var (`TALOS_WORKER_SUPPORTS_SEALING`) that no compose file, chart or installer set, so every self-registered worker reported `false`, including the dev fleet that has claimed sealed envelopes under `required` since 2026-07-06. The static-ring path already rendered `null` there on the argument that "the ring cannot make that claim"; the registered path was making the claim and making it wrong. A registered worker supports sealing BY CONSTRUCTION — the registration proof is signed with the same key a claim is signed with, and the claim consults nothing else — so the bit is now derived (`true`), the env var and its helper are gone, and the wire field stays (it is bound into the signed proof) for a build that can register but not claim, of which none exists. `talos-jobs` (668 lines, `start_processor` with zero callers, a stub `process_next_job`) and `talos-db-monitor` (115 lines, `QueryMonitor` with zero callers) were DELETED with their 3-line controller shims; MCP-704 had kept them "so future wiring doesn't have to re-import" and none came. Migration `20260911120000` drops `jobs` and `dead_letter_jobs` — 0 rows each, their only reader deleted — and with them three indexes and the RLS policies the org-id migration had attached.

* **Package L (2026-09-11, follow-up PR): the chart now REFUSES the Postgres connection arithmetic it used to merely state.** Package G's G5(a) set `controller.database.maxConnections: 20` and recorded "HPA max 6 × 20 = 120 STILL exceeds 60 — stated". A statement in a values comment is not a control: a bare-helm operator enabling in-cluster Postgres with the chart's DEFAULT autoscaler (on, max 6) rendered cleanly and would exhaust the 60-connection server the first time the HPA scaled out, every new controller pod crash-looping on "too many clients already". `templates/postgres/configmap.yaml` now `fail`s when `(autoscaling.enabled ? maxReplicas : replicaCount) × pool + 6 reserved (superuser 3, migrations Job 2, backup pg_dump 1) > postgres.config.maxConnections`, naming the three remedies with the computed bounds. The phase-1 installer values (1 controller, autoscaling off: 26 of 60) pass. **Check 5 grew two legs and lost none**: `postgres.enabled` takes the `# no-render-toggle` marker (it gates a `fail`, the ollama precedent), so 5(b) no longer renders `postgres/*`; 5(c) renders `values-phase1.yaml` — the only shipped in-cluster configuration — and 5(d) is a NEGATIVE render (default HPA × pool 20 against 60) that must REFUSE with the arithmetic message, because a `fail` guard that never fires is a green tick over nothing (checks 64/65). `--count` stays 88. Limit: the guard sees only what the chart deploys — a managed Postgres's ceiling is invisible to it, and values.yaml says so.

* **A backlog that arrives without a boot is still a backlog (package M, 2026-09-11).** The scheduler's tighter startup ceiling (`SCHEDULER_STARTUP_MAX_CONCURRENT`, default 4) keyed on PROCESS AGE alone — "the first poll since boot" — while the M6 comment above the steady semaphore names the case that misses in its first sentence: "controller downtime OR a clock catch-up". Measured 2026-09-10: the host was suspended 10:56–12:06 UTC (every Prometheus job, Prometheus included, has no samples; the dispatch counter climbed 17 → 28 with no reset, so the process never restarted), the controller resumed with `first_poll_done` already spent, one poll claimed **ten** schedules (daily crons 53 min late, a `*/15` cron 65 min late), labelled every one `steady`, drained them under the 16-wide steady ceiling that had not bound on the 2026-08-10 herd of 15 either, and `TalosSchedulerStartupHerdNotAbsorbed` — selecting `phase="startup"` — saw a steady-state batch. Six of the ten carried LLM nodes into the single-slot Ollama; the #792 gate queued them (16 acquires, 673 s total wait, p90 96 s, 0 wait-expiries in that window) and two hit their 120 s node timeout while queued — the documented residual of #792, now with its first live sample. The phase is now `talos_scheduler::classify_dispatch_phase(first_poll, max_overdue_secs)`: boot wins (`startup`, whatever the lateness); otherwise a batch whose MOST overdue row is ≥ `CATCHUP_OVERDUE_SECS` (six 15 s polls = 90 s; ordinary lateness is bounded by one interval, a failed poll adds one, and a `*/15` cron is the most frequent the platform admits) is `catchup`; else `steady`. Lateness is `EXTRACT(EPOCH FROM NOW() - next_trigger_at)` on the verbatim claim statement — the DATABASE clock, the same one the `<= NOW()` predicate used. Both backlog phases take the startup permit through ONE predicate (`phase_takes_backlog_permit`), so the semaphore and the metric label cannot disagree; the alert selects `phase=~"startup|catchup"` in all three arms and keeps its name; `talos_scheduler_dispatches_total` is fifteen pre-seeded series, the `catchup` five sitting at 0 forever on a fleet that never suspends — exactly the series an unseeded registry would omit. The threshold is a CONSTANT, deliberately not a knob: the cost of a false `steady` is this herd and the cost of a false `catchup` is a mislabelled batch too small for a 4-wide ceiling to bind. Guards: pure-function unit tests at the boundary; `controller/tests/scheduler_catchup_phase_tests` (CTRL_TESTS per 64b) driving the real SQL against a clone in both directions plus the boot-flag precedence; and two SOURCE PINS, stated as textual — the permit site must call the shared predicate (a `== SCHEDULER_PHASE_STARTUP` revert there is behaviourally identical on every boot and drops the catch-up batch onto the steady pool, and no test can drive the spawned task's permit without live NATS) and the herd alert's three `expr` selectors are read out of the chart file at compile time (#630's rule). **Not done, stated:** the LLM herd itself. A 4-wide ceiling over six LLM-bearing workflows on a one-slot backend still queues; stagger/jitter of colliding schedules is the complement #792 named and this package does not touch the user's crons. And the 2026-09-10 12:05 window is a RESTART-DAY sample — the first non-restart post-gate noon is 2026-09-11 12:00 UTC.

* **The alert kept the cadence the review changed (package S, 2026-09-11).** #794 moved the crypto-orphan sweep (`CryptoInvariantGauge`) from 60 s to an hour for cost — three full-table anti-joins a minute was the finding — and left `TalosCryptoOrphanDetectorBlind` at `time() - stamp > 600` under a comment that still read "the sweep runs every 60s". A healthy controller is 0–3600 s stale between hourly sweeps, so the alert was in `pending` from minute 10 and FIRING from minute 25 to minute 60 of every hour: measured in Prometheus, **15.3 of the 27 hours** since that deploy (1831 samples at the group's 30 s interval), **0 in the thirteen days before**, on the one `observability` alert whose job is to say the three `critical` data-loss detectors are blind — check 69's permanently-red trap, on a rule whose own comments argue against that trap at length. The threshold is now **7800 s** (two consecutive missed hourly sweeps plus ten minutes of scrape slack; with `for: 15m` that is ~2h25m of blindness before firing, against the `for: 8h` on the alerts it guards), the cadence is a named constant (`CRYPTO_ORPHAN_SCAN_INTERVAL_SECS`; `CATALOG_MISSING_WASM_SCAN_INTERVAL_SECS` beside it), and **the coupling is a compile-time pin** (`blind_detector_thresholds_match_the_sweep_cadence`, #630's rule): each blind detector's `expr` threshold is read out of the chart file and must sit within **[2, 8] × its sweep interval** — the lower bound is this defect's guard (never fire between two completed sweeps), the upper keeps it a detector. The five stale "60s scan" / "first tick is skipped" sentences in the crypto group were corrected; a promtool fixture drives a stamp that advances once an hour (never fires) and one that stops (fires at two missed sweeps + `for`), and on the old threshold the healthy case fails at 59m, 1h59m and 2h59m — the live defect, reproduced offline. **And the fixture had been green over the defect**: its three crypto-blind cases fed `0+60x…`, the cadence the ALERT assumed, so they proved the rule self-consistent and nothing about the producer — a fixture that models the consumer's assumption is not a test of the coupling. The same run found the (then not-CI-wired) chart fixture already red on pristine main with FOUR cases, all #809's: that PR reworded the herd alert's summary/description and the breaker's runbook step 4 and never re-ran `promtool test rules`, exactly the rot its own header predicts; repaired here, and the fixture is green again. **Not changed**: the three data-loss alerts' `for: 5m` / `keep_firing_for: 5m` (an hour cannot move a count that only an operator action or a deploy moves — #794's own argument), the catalog blind detector (1800 s against a 300 s sweep already sits at 6×), and the cadence itself.

* **A fixture nobody runs certifies nothing (package T, 2026-09-11).** Both promtool fixtures said "NOT WIRED INTO CI — promtool is not available on the CI runners" for six weeks; the runners have Docker (every `services:` block in `quality.yml` is a container), so the command both headers told a human to run would always have run there. In those six weeks the chart fixture went red on main twice without anyone noticing — #809's reworded annotations (four cases) and the crypto-blind cases modelling a 60 s sweep a day after it went hourly — both caught only because package S ran it by hand. Now `make test-alert-rules` (promtool `check rules` over both rule files + `test rules` over both fixtures, from the digest-pinned `prom/prometheus:v2.48.0` — 3.x fails herd fixtures 2.x passes, so the pin is load-bearing) and the `alert-rules` job in `quality.yml` that calls it: one command, local and CI. Mutation-proved (a reverted expectation fails `test rules` naming the case; a broken expression fails `check rules`). **This supersedes the two sentences above that call the fixtures "NOT CI-wired (no Prometheus toolchain on the runners)"** — in check 66's entry and the PromQL absent-vs-zero bullet — which stay as written because `check-engineering-log.py` keeps base lines byte-identical; read them as history.

* **Two audit tables, one nobody reads and one nothing writes (package V, 2026-09-11).** `admin_event_log` — 85 rows, 16 event kinds across `workflow` / `module` / `actor` / `ml_model` / `mcp_agent` — had FOUR writers and NO operator-facing reader: it sits on the platform-admin query tool's DENY list and no MCP tool selected from it, so the "audit-log scrub" step in `docs/security/pentest-scope.md` was doable only with psql. It is now rendered where the operator already looks: `get_workflow_audit_trail` gains `admin_action` events (with `admin_event_type` and `by_user_id`, under the `Readings` ledger as `events.admin_action`), `get_module_history` gains `admin_events` (+ `admin_events_unreadable`, disclosed as `null` never `[]`), via one repository read `list_admin_events_for_resource(resource_type, resource_id, limit)` that filters on the RESOURCE (ownership is the caller's check) and renders the event's own user as the actor of the change. `actor` / `ml_model` / `mcp_agent` events are stated as still unrendered. `audit_events` — "Primary security audit ledger" in `docs/security/architecture.md`, one of "all 4 audit tables" in the threat model, an immutability trigger, three indexes, a CSV export and a summary query in the SOC 2 evidence scripts — has held **zero rows since 2026-03** and nothing in the workspace writes it: the execution ledger is the worker's S3 WORM hash chain. The SOC 2 summary query selected `details` and `created_at`, two columns that table never had — check 88's class in a `.sql` script, so it could never have executed. DROPPED (migration `20260911160000`, package K's shape), removed from check 47's list and the SOC 2 scripts (which now summarise `admin_event_log` and point at the WORM ledger's sweep metrics), docs corrected to three tables plus the S3 ledger. **And that dead query was one of SIX in `scripts/soc2/verify-controls.sql`** — `secret_audit_log.created_at` (the column is `"timestamp"`), `webhook_triggers.rate_limit` (never existed; `max_requests_per_minute`) with jsonb operators on a `text[]`, `FROM wasm_modules` and `FROM node_templates` (both dropped by Phase 5 `20260423050000`), `execution_approvals.created_at` (`requested_at`) — so six of the verifier's ten sections could not execute and the script had never once run end-to-end on any database this repository can produce. Every block is repaired; it now exits 0 under `ON_ERROR_STOP=1` against a migrated scratch database and against the live one. **Deliberately NOT added to check 88**: the probe walks `sqlx` call sites in Rust, and a psql script with `\echo` directives needs a different runner — the `ON_ERROR_STOP=1` run is a snapshot recorded in the PR, not a gate.

* **The 65% of the admin audit log no per-resource reader could reach (package W, 2026-09-12).** Package V rendered `admin_event_log` where an operator opens a LIVE workflow or module. Measured the morning after it deployed: **55 of 85 rows** had no surface at all — 21 `workflow_deleted` and 8 `module_deleted` events whose resource no longer exists (there is nothing to open `get_workflow_audit_trail` on), 7 bulk events with a NULL `resource_id`, and every `actor` (9), `ml_model` (13) and `mcp_agent` (2) row. Package V also under-counted the writers: SIX, not four, across TEN resource types (`workflow`, `module`, `actor`, `ml_model`, `api_key`, `mcp_agent`, `user`, `execution`, `system`, `worker_provisioning_token` — the last written with `user_id NULL` by the CLI). Now: **`list_admin_events`**, one page of the table newest first (`created_at DESC, id DESC` — check 28), filterable by `resource_type` / `event_type`, with `resource_present` (`true` / `false` / `null` = unknown, from the resource's own table, the `execution` type checked against live AND archive per #748) so "who deleted what" is finally answerable. **Tenancy is the event's `user_id`** — the table has no RLS and no owner column, so the default scope is the CALLER's own actions; `all_users=true` is gated on `users.is_platform_admin` (the `get_secret_access_log` precedent — the agent's `*` capability is deliberately NOT enough) and REFUSED rather than narrowed, and it is the only scope that reaches system-authored NULL-user rows. An unreadable log is an ERROR to the caller, never an empty page. The two remaining per-resource homes gained the same block: `get_actor_summary` (`admin_events` beside the ceilings it reports — the WHEN and WHO of every ceiling change; `null` + `admin_events_unreadable` on failure) and `ml_get_model_card` (`admin_events` through its existing `Readings` ledger). **Measured and NOT changed on the same pass**: the fuel-headroom detector's statement (`AnalyticsRepository::get_node_fuel_headroom`, the #3 statement by total time in `pg_stat_statements`, 92 ms mean at 178 calls / 48 h) re-joins `workflows` once PER ROLLUP ROW for the name — 67 760 of its 70 342 buffer hits — and an aggregate-first rewrite measured **59 → 35 ms with byte-identical rows (59 of 59, symmetric difference 0)**; declined as a package because it is 25 ms on a 15-minute tick and the interactive caller is one report, recorded so the rewrite is not re-derived. Also measured: `LowCacheHitRate` goes `pending` for a few minutes after every worker restart (cold module cache; 4 pending stretches, 0 firing, in 48 h) and clears inside its `for: 10m` — benign, stated.

**Deliberately NOT done / recorded.** (A post-auth DLQ enqueue site was listed here and is CLOSED — #796's `capture_post_auth_drop` stamps every below-the-gate dispatch failure `authenticated: true`; the pre-auth breaker/rate-limit drops stay un-replayable by design.) (TOTP/OTLP AAD domain separation and the three v3 writers on org data were listed here and are CLOSED by #797 — package C above. `frontend/src/generated/*` was listed as not regenerated and is CLOSED: `quality.yml` runs `npm run codegen && git diff --exit-code` on every PR, so a stale snapshot cannot merge.) `set_actor_llm_tier_ceiling` loosening on a no-2FA credential (product call); webhook POST retry default 3 (pinned contract); Unicode look-alike delimiters.

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
  **Burn-down 2026-09-11 (no new number — `--count` stays 88): `BASELINE_DEAD` went 10 → 3.** The baseline had carried the same ten names since the check landed: registered 2026-05, never incremented, referenced by no alert or dashboard (58(b) verifies that on every run). Three are now WIRED at their single recorders and seeded over compiler-closed sets in `talos_metrics::security` — `talos_auth_2fa_attempts_total{status}` at `TotpService::record_2fa_success/failure` (the two recorders every verification path already calls, six sites), `talos_api_key_validations_total{status}` at every verdict in `ApiKeyService::validate_key` (`expired` only when EVERY candidate was expired; a DB failure mid-validation is not a verdict), `talos_rate_limit_hits_total{type}` at all four limiters (per-IP incl. the GraphQL 200 variant, global, api-key, webhook). Four were DELETED rather than wired: the two `trigger_id`-labelled webhook series (a per-row label this file otherwise forbids; `webhook_request_log` is the per-request record) and the two cache series (a comment named three caches; none was wired in four months). Guards: `security_counters_are_seeded_and_their_recorders_move_them` (exhaustive over `ALL`, and asserts the four deleted families no longer render); `controller/tests/api_key_tests::validate_key_verdicts_move_the_seeded_counters` drives the PRODUCTION path for all four verdicts plus the api-key limiter kind — check 58's wrapper limit closed for that surface; the 2FA and rate-limit sites are SOURCE PINS, stated as such, because driving them needs a user row + Redis or an axum `Next` + the production env gate. The remaining three followed the same day and **`BASELINE_DEAD` is now EMPTY and must stay empty**: `talos_workflow_execution_duration_seconds{status}` is observed at all FIVE workflow finalizers (both repositories' `mark_execution_completed`/`mark_execution_failed`, plus `fail_execution_unless_terminal`, which until then was the one failure path that did not even count on `talos_workflow_executions_total`), `talos_module_executions_total{status}` (labels `completed|failed|timeout|cancelled` = the column's own terminal states; `trigger_type` dropped — it reads `webhook` on all 55 279 rows) and `talos_module_execution_duration_seconds{status}` at every module finalizer (complete / fail / timeout, both worker-result paths, the stuck sweep per swept row, the engine's born-`cancelled` INSERT). **The duration is what the finalizing UPDATE itself RETURNS** — `EXTRACT(EPOCH FROM (completed_at - started_at))` by the database clock, so the histogram describes the same row and the same clock as the status write; a finalizer that does not stamp `completed_at` passes `None` and moves the counter only — unknown is not zero seconds. Two `query!` macros became function-form `sqlx::query` so the RETURNING projection needs no offline-cache regeneration (check 88 PREPAREs them instead). Counters seeded over `ModuleExecutionOutcome::ALL`; histograms deliberately not (a quantile needs no first observation — the MCP decision). A production-path DB test drives every finalizer.
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
  **Roots widened 2026-09-11 (no new number — `--count` stays 88):** `SQL_PREPARE_ROOTS` shipped as a hardcoded list of the repository crates plus the check-52 family and covered 949 of the workspace's 1227 static statements; it is now a glob over `controller`, `worker` and `talos-*` `src/` (140 roots). The 278 statements it added — `talos-ml` 85, `talos-oauth` 29, `controller` 24, `talos-engine` 20, `talos-webhooks` 19, `talos-scheduler` 18 … — ALL PREPARE: zero findings, a gate widening and not a bug fix, stated as such. Cost 0.6 → 0.9 s; the zero-roots and zero-statements arms still FAIL rather than skip. Base line above left byte-identical for `scripts/check-engineering-log.py`'s losslessness leg, which is why this is a separate line.

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
