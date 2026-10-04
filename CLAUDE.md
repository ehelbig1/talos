# Talos Development Guidelines

## Build & Test Commands
```bash
make up-dev          # Start all services
make up              # ↑ the target that exists: there is no `up-dev` (line above kept byte-identical for check-engineering-log.py)
make lint            # Fast gate: rustfmt + structural lints + cargo-deny (lint-full adds clippy)
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

**A Google disconnect revokes at Google only for the account's last connection** (2026-10-02). Google keeps one grant per (account, OAuth client) and a revoke ends all of it — tested live. `OAuthCredentialService::revoke_and_cleanup` is the one place that decides, via `talos_oauth::google_grant`; do not call Google's revoke endpoint anywhere else, and a new Google integration keys its connection by the shared account-id derivation and records `account_email`.

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
- `essay_outline` — content-pipeline-weekly outlines (added 2026-09-29)

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
* `ttl_hours` (number) — TTL from now. An explicit value always applies.
  Omitted, a `semantic` write never expires and every other type gets 168
  (until 2026-09-30 omitted meant 168 for `semantic` too)
* `skip_if_unchanged` (bool, default false; 2026-10-03) — when the live row
  already holds this value, memory type and metadata, nothing is rewritten (no
  embedding, no graph extraction, `updated_at` untouched): the row is marked
  `checked_at = now()` and its expiry renewed. A freshness contract
  (`requires_fresh`) reads the later of `updated_at` and `checked_at`, so a
  writer that runs often and changes rarely should send its full value every
  run with this flag rather than writing only on change — otherwise a quiet
  day reads as stale. A non-boolean is refused (the write is dropped).

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

The decisions are kept in `docs/engineering-log/DECISIONS.md`, not in this file
(moved 2026-10-03, operator decision). Until then this section carried them:
134 KB of a 250 KB file, read at every session start, every re-read after a
context compaction and every sub-agent brief. They are one digest per defect
class — what was decided, what was measured and REJECTED, what is latent on this
fleet, what was deliberately NOT done — each pointing at the narrative that
produced it.

**Before changing an area an index line below names, read its digest in
`docs/engineering-log/DECISIONS.md`.** That record is what stops work being
redone and a rejected idea being proposed again; it is no longer in context, so
the read is the rule. `grep -n '<identifier>' docs/engineering-log/DECISIONS.md`
finds the paragraph. `scripts/check-engineering-log.py` (check 96) proves the
move lost no line, that every decision marker is still named by a digest, and
that every digest has an index line here.

**Rules for adding to this file** (changed 2026-09-25). CLAUDE.md had become
the one file nearly every change edited — 57 of the 58 commits before this
rule touched it, most to append a package bullet — so parallel PRs conflicted
here and every session paid, at start-up, for the whole record.
* A package records its decisions in its OWN file,
  `docs/engineering-log/packages/<YYYY-MM-DD>-<slug>.md` (that directory's
  README says what goes in one): the decisions, measured populations,
  `deliberately NOT`, latent claims and stated limits a package bullet used to
  carry. A new file conflicts with nothing.
* CLAUDE.md changes only when a package creates or changes a RULE a future
  session must follow — in a sentence or two, in the section that owns it.
* Before working in an area, `grep -ril <subsystem> docs/engineering-log/` —
  the record is searchable; it is not read at session start.
* If you cannot tell whether a paragraph is a rule or a story, it is a rule —
  leave it here.

**Index** (digest — what it covers):

* **The workflow-liveness / child-run family** — readiness scoring, `workflows.status` vs `is_enabled`, archiving and the draft auto-archive sweep, sub-workflow child runs (`sub_workflow_runs`), SLA reports, dispatch of archived workflows
* **The swallowed-read / fail-open family** — a read collapsed into a default (`unwrap_or`, `.ok()`), gates that must refuse when their rule is unreadable, the `Readings` ledger in reports, MCP per-tool metrics and error kinds
* **The audit-chain verifier** — the WORM audit ledger, chain verification and its credentials, `dispatch_attempt`, standalone module jobs, the hourly sweep
* **Artefacts that describe a system that does not exist** — documented env vars with no reader, chart Secrets, the `frontend/schema.graphql` snapshot, readiness advice
* **SQL that has never once executed** — runtime `sqlx::query` strings, check 88, the trigger-time liveness gate (`is_dispatchable`)
* **Failures nobody can see** — background-task supervision (`spawn_supervised`), signed-RPC metrics, push-channel module bindings, process and security counters, execution finalizer counters
* **A documented knob whose advertised range is inert** — rank-training lookback and fetch cap, config knobs bound by a constant, deleted dead env vars
* **The database was the last unmeasured layer** — `pg_stat_statements`, `get_sql_statement_report`, check 88's roots, platform-admin gating
* **A per-call timeout spent on somebody else's inference** — the local-LLM gate (`TALOS_LOCAL_LLM_MAX_IN_FLIGHT`), Ollama concurrency, the exchange timeout, schedule herds
* **The whole-codebase review** — the 2026-09-10 review: signed fuel, the worker result cache, reserved keys, dispatch-time capability ceilings, sandbox posture, webhook dedup and DLQ, the chart, Neo4j, memory spotlighting
* **The package record, 2026-09-10 to 2026-09-25** — one title line per package C..EV (signing, tenancy, RLS, DEKs, audit records, budgets, replicas, ceilings, egress, engine routing); the full bullets are in `2026-10-03-package-record.md`
* **The lint checks' regression narratives** — why checks 74 / 88 / 83 / 65 are specified as they are; compressing the lint entries further was measured and closed
* **Structural lint checks** — the one-line index of checks 1..97 (check 54 reads it there)

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

**An Ollama CLOUD model is not local (2026-09-30).** Ollama serves a
`:cloud` / `-cloud` model, or any model its `/api/tags` lists with a
`remote_host`, by forwarding the prompt to `ollama.com`. The one home is
`talos_local_inference::locality::model_locality`: every worker path to the
local Ollama (`complete*`, `complete-with-tools`, `start-stream`,
`start-tool-stream`) calls `TalosContext::admit_local_model` for a tier-1
actor, and `talos_llm::OllamaClient::chat` refuses such a model for every
caller. A model the listing does not contain, or an unreadable listing, is
refused too. A new local-inference call site must go through one of the two.

**Defense in depth on the controller side:** `build_encrypted_secrets_for` takes `max_llm_tier` and SKIPS the `resolve_llm_keys` prefetch entirely when `Tier1`. Tier-1 jobs never have an Anthropic/OpenAI/Gemini key on the wire (encrypted or otherwise) — bounds blast radius if a future bypass slips.

**Stamping the tier on a workflow execution:** ALWAYS use `talos_engine::actor_binding::apply_actor_to_engine(&actor_repo, &mut engine, actor_id)` (moved from `ActorRepository` in 2026-07 — lint check 51 forbids the repo→engine dep edge) — it sets `actor_id` AND `max_llm_tier` together and fail-closes to Tier-1 on DB error. Never call bare `engine.set_actor_id(aid)` — lint check 29 catches it (the setter is confined to `talos-workflow-engine/` and `talos-engine/src/actor_binding.rs`).

**Module-bound dispatch** (Gmail/GCal/webhook push notifications) is intentionally Tier-2 default — those paths fire individual modules without an owning actor. Operators who need tier-1 enforcement for inbound-event processing wrap the module in a workflow with an actor that has `max_llm_tier=tier1`.

## Secret Handling Rules (CRITICAL — security invariant)

**Plaintext secret values MUST NEVER leave the controller host** except through two audited paths:
1. **Outbound HTTP headers** — `vault://` resolution places the secret into a header for an external API call; the `Zeroizing<String>` is cleared after use.
2. **Tier-2 `expose_secret`** — explicit opt-in per module (`allow_tier2_exposure: true`), rate-limited (10/execution, 100/user/day), audit-logged at WARN level. Currently hardcoded to `false` across all engine dispatch paths.

**Every engine dispatch path MUST call `build_encrypted_secrets()`** (or the equivalent inline block) to populate the job's `encrypted_secrets` field. Sending `Default::default()` means the module silently loses access to all secrets — vault:// headers fail with `Notfound`, LLM calls fail with missing keys. This was a real bug in loop-node dispatches fixed 2026-04-16. When adding a new dispatch path (new system-node kind, new parallel executor, etc.), grep for `encrypted_secrets:` in `parallel.rs` and verify the new site matches the existing pattern.
**Correction, 2026-09-26:** `ParallelWorkflowEngine::build_encrypted_secrets()` had no callers and was DELETED; the one home every dispatch path uses is `secrets_pipeline::build_encrypted_secrets_for` (`build_dispatch_secrets_for` when sealing). Read every mention of `build_encrypted_secrets()` in this file as that function. The line above is kept byte-identical for `scripts/check-engineering-log.py`.

**Secret flow through the system:**
- Controller: `SecretsManager::get_module_secrets(node_id)` + `get_secrets_by_paths(vault_paths)` + `prefetch_llm_vault_keys(user_id)` → plaintext `HashMap<String, String>` → `EncryptedSecrets::encrypt(map, key)` → AES-256-GCM ciphertext in `JobRequest.encrypted_secrets` → NATS publish.
- Worker: `EncryptedSecrets::decrypt(key)` → plaintext `HashMap` loaded into `SecretProvider` DashMap → WASM guest receives opaque `u64` handle only (Tier-1), never the string.
- No MCP handler, GraphQL query, or REST endpoint returns plaintext secret values. `get_secret` is internal-only. MCP is **read-only for secrets** (MCP-1201): `set_secret` / `delete_secret` / `set_secret_namespace` / `set_secret_expiry` / `rotate_secret` were removed because MCP API keys are long-lived bearer tokens with no 2FA equivalent — secret writes would have bypassed the `require_2fa + SecretsWrite` discipline the GraphQL surface enforces. Mutations go through `talos-api/src/schema/secrets/mutations.rs`; MCP retains the read surface (list, namespaces, usage, health, normalize). `refresh_oauth_token` is the lone MCP write that touches vault — provider-side token rotation, no MCP-supplied value crosses the boundary. The GraphQL `Secret` type has no `value` field.
- DLP `redact_json()` is applied to module execution output before DB storage (catches `sk-*`, `ghp_*`, Bearer tokens, etc.).
- Audit logs record `key_hash` (SHA-256 of path), never the value.
- A `secret_audit_log` row is written BEFORE its secret is deleted: the table's row security admits a row only while the parent secret exists, so an audit insert after the `DELETE` is refused under `talos_app` and rolls the delete back (2026-10-02).
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
**A row sealed across more than one write** (a `module_executions` row seals input at start and output at completion under one shared key id and format) must seal every later slot under the key and format the row ALREADY names — `SecretsManager::encrypt_value_aad_under_row_key`, via `encrypt_output_for_row` — never a freshly resolved one (package CJ).

**Every DEK wrap is bound to its `encryption_keys` row (RFC 0013).** A new
writer of `encryption_keys` wraps with `DekRowIdentity::new(id, org_id).bound_aad()`
(`talos_secrets_manager::dek_wrap`), generates the `id` BEFORE wrapping, and
stamps `BOUND_WRAP_FORMAT` (2, the only value `CHECK` allows); a reader calls
`dek_wrap::ensure_bound(wrap_format)` and unwraps with the row's `bound_aad()`.
`KekProvider::{wrap_dek, unwrap_dek}` take the AAD as a required argument.

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
- **Correction to the line above, 2026-09-24 (package EJ): an empty `allowed_methods` now DENIES every verb.** The base line is left byte-identical for `scripts/check-engineering-log.py`'s losslessness leg, which is why this is a separate line. Two clauses of it are now false: the enforcement points are **FIVE**, not three (`host/http.rs` fetch + fetch_all, `host/graphql.rs`, `host/webhook.rs`, and `host/http_stream.rs`, the last added by EJ because an ungated SSE connect would have left an undeclared module able to egress); and they no longer "read empty as 'allow every verb'" — `talos_workflow_job_protocol::method_permitted` denies on empty, so `allowed_methods` is no longer the odd one out and the stated asymmetry with `allowed_hosts`/`allowed_secrets` is CLOSED. What is UNCHANGED is the retry verdict: `methods_are_read_only` still returns `false` on empty and an undeclared module still earns 0 retries — for the opposite reason, that it makes no HTTP call at all, so there is nothing for a transient retry to re-send.
- **Pipeline steps retry too.** `execute_pipeline`'s per-step loop honors per-step `max_retries` gated by the transient classifier — do not re-hardcode step `max_retries: 0`. The transient classifier must match BOTH `"timeout"` AND `"timed out"` (the worker's own step-timeout message uses the latter).
- **A controller-dispatched job is NOT retried in-process by the worker (2026-09-25).** `RetryPolicy` (`talos-worker-runtime`) has no `Default`: an in-process retry re-runs the WHOLE module on guest-influenced error text ("timeout", "503") and looks at nothing else, and it multiplied the controller's method-aware re-dispatch. The NATS path passes `RetryPolicy::controller_dispatched()` (zero), pinned at its call site by `worker/src/retry_policy_pin.rs`; `talos_workflow_engine_nats::execute_job_with_retry` is the ONLY retry loop for a dispatched job. The embedded rehearsal surfaces (`run_sandbox`, `test_module`, scratch sessions, module replay, GraphQL `testModule`) still pass `RetryPolicy::in_process_transient()`, which is NOT method-aware — recorded, not changed.
- **The attempt-window arithmetic has ONE home: `talos_workflow_engine_core::attempt_window` (2026-09-06).** How much of a workflow's wall-clock budget one dispatch attempt may occupy is asked on two surfaces — the DISPATCHER (`talos_workflow_engine_nats::execute_job_with_retry`, where a wrong answer is a real cancellation) and the VALIDATOR (`talos_workflow_validation::retry_envelope_overrun`, where a wrong answer is advice an operator acts on). They had two implementations. The dispatcher's: `min(allowance, remaining − BUDGET_RESERVE_SECS(2))`, where `allowance = timeout_secs + TOKIO_WRAP_GRACE_SECS(5)`. The validator's: `envelope_secs <= budget_secs`. **They disagree by 7 s at the boundary**, so a node configured at 120 s inside a 120 s budget was reported as fitting and clamped to 117 s (`as_secs()` truncation) on attempt 1 of every run — measured live on the dev fleet: **9 such nodes across 3 ACTIVE workflows, 2 326 clamped attempts per 48 h** (`pa-ask-email` 1848, `pa-followup-approval-notifier` 382, `ops-critical-notifier` 96), every one on `attempt=1` of a run that then completed in under a second. `clamp_attempt_timeout`, `AttemptWindow` and the three constants MOVED to core (they are not copies — the dispatcher re-imports, `dispatch_allowance_secs` states the `+ 5` once), and the validator now SIMULATES the configured attempt sequence through the same `attempt_window_for_remaining`. Do not re-derive either half.
  - **Three outcomes, and the middle one was unsayable before.** `AttemptFit::Full` (silent) / `Clamped` (every attempt starts, at least one is cut short — a real finding, lower severity, category `attempt-window-clamped`) / `Truncated` (an attempt is never dispatched — the historical `retry-envelope` category). Fleet effect, measured: the old check reported **7** nodes; the new one reports **16** — 4 truncated (a strict SUBSET of the old 7) and 12 clamped, of which 3 were previously reported as the SEVERE finding (correctly downgraded: one 4 x 120 s node in a 450 s budget gets all four of its attempts, the fourth cut to 38 s) and 9 were reported as nothing at all. `ValidationSeverity` has only `Error`/`Warning`, so "lower severity" is expressed in the category and the wording; adding an `Info` variant would move every counter and response shape that reads a `ValidationResult` and was deliberately NOT done. `max_retries_within_budget` searches the same simulation, so it stays the exact inverse — and it MOVED by one retry on shapes the old formula's slack fitted an extra attempt into (`(120, 500, 240)`: 1 → 0).
  - **The prose in BOTH crates was one release behind the code.** `describe_retry_envelope_overrun` and `talos-mcp-handlers`' `describe_retry_bound` both said *"the retry loop has no view of the workflow deadline … the whole execution is dropped — discarding every sibling node that had already finished"*. False since #686 (2026-08-27, the same day that text was written): a clamped attempt that times out, and an attempt refused for want of budget, are both ORDINARY NODE FAILURES the engine routes (error edges, `continue_on_error`, DLQ) with sibling results kept. A single-string grep finds only ONE of the two — the handler's copy is reworded — so a fix to one crate really is a drift.
  - **The residual, stated rather than dropped.** The budget is still an OUTER `tokio::time::timeout` that drops the reactor future, and `BUDGET_RESERVE_SECS` makes the failure RECORDING likely, not certain: `handle_node_failure` awaits a `node_failed` INSERT, the DLQ write and a sibling reap, and a slower failure path still loses the race. The clamp covers module dispatch ONLY — `sub_workflow`/judge/ensemble nodes awaited inline are unclamped (the validator skips `system:*` nodes, so it claims nothing about them), and **`engine_dispatch_pipeline.rs` passes `deadline: None`**, so the chain path is unclamped too — dormant by config (`ChainDispatch::Disabled` at every production entry point) and RECORDED, not fixed.
  - **The clamp WARN is now attributed by cause.** `DispatchJob::budget_secs` (stamped beside `deadline` from the same `secs` on `ExecutionProgress`) feeds `clamp_cause`: `Configuration` (the allowance could never have fitted, even at t=0 — a graph problem `validate_workflow` now reports) logs at **debug**; `Consumption` and `Unknown` stay **warn**. `budget_secs` is ATTRIBUTION ONLY — it never enters the clamp, so `None` changes no timing, and `Unknown` is never demoted. **No metric was added**, and that is a measurement: `talos-workflow-engine-nats` has no `talos-metrics` dependency (it is reachable only transitively through `talos-workflow-engine`, which Rust does not permit), so a series would cost a new direct dependency edge — recorded and declined, which means the consumption clamp remains prose-only and cannot be alerted on.
  - **No lint was added, and here are the numbers so nobody re-measures.** "Clamp constants or `clamp_attempt_timeout` defined outside core" reports **1 file** on pristine main and 0 after — population ONE, which is the bar this repo does not ship at; the structural answer (one `pub` home, the constants deleted from the dispatcher) is already stronger. "An `envelope_secs <= budget` comparison outside core" reports 2 lines on main of which 1 is a legitimate test assertion (50% precision) and **3 on the FIXED tree, all of them the new comments explaining the fix** — check 73's self-report trap. `--count` stays **86**. Two mutations are open and measured SURVIVORS, both in the loud direction: re-inlining `job.timeout.as_secs() + 5` at the dispatch site is behaviourally identical and no test can see it (the guard is that the constant no longer exists in that crate), and passing `None` for `budget_secs` merely restores the WARN.

- **Fuel accounting reads the signed result, never the output (2026-09-29).** `module_executions.fuel_consumed` and `execution_cost_rollup` (the hourly fuel budget's table) have ONE writer, `talos_cost_attribution`, fed per VERIFIED attempt by the NATS dispatcher's `FuelSink` and, for module-bound dispatch, by the webhook router and result observer; each reads `talos_workflow_job_protocol::spent_fuel`. Do not read `__fuel_consumed__` out of a node output for accounting: the worker can stamp it only into a JSON object, and a failed attempt has no output. A learner over the rollup reads `outcome = 'completed'` only; a budget reads every row.
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
- **A deployment can turn module compilation off** (`TALOS_MODULE_COMPILATION=false`,
  2026-10-03): registry-only, no toolchain is run over module source. A new
  path that runs one gets its slot from `CompilationService::acquire_slot`,
  which is where the switch is enforced; a handler that turns a compile-service
  `Err` into a response calls `talos_compilation::caller_facing_service_error`.
  `TALOS_REGISTRY_URL` is read only through `talos_config::registry_url()`.

## WASM Module Development Rules (MUST follow)
- NEVER use top-level `serde_json::Value` to parse upstream payloads. Use typed `#[derive(serde::Deserialize)]` structs — 3-10x cheaper in WASM fuel. The `Value` type allocates a `HashMap<String, Value>` per JSON object; typed structs skip unneeded fields entirely.
- ALWAYS set explicit `max_fuel` on every workflow node. Default fuel (1M-5M) is rarely correct. Use `fuel_budget` in `hot_update_module` / `compile_custom_sandbox` to auto-calculate from expected payload shape.
- ALWAYS use `format=metadata` (Gmail) or field-limited queries (Jira `fields` param) when full response bodies aren't needed. Smaller payloads = less fuel + avoids the 65KB input limit.
- ALWAYS cap collection sizes: `MAX_RESULTS`, `take(N)`, thread caps. Match caps to schedule cadence (e.g., 15-min poll → `newer_than:15m`, not 30m).
- ALWAYS specify `capability_world` explicitly when compiling modules. Use least-privilege: `minimal-node` unless HTTP/secrets/etc. are needed.
- ALWAYS validate required config keys early in `run()` with clear error messages (e.g., `ok_or("Missing AUTH_HEADER config")`).
- ALWAYS use versioned API endpoints (e.g., `/rest/api/3/` not `/rest/api/2/`). Pin to the latest stable version to avoid deprecation (HTTP 410).
- ALWAYS run `validate_workflow` after modifying node configs. ALWAYS run `test_workflow` with assertions before considering a workflow production-ready.
- A catalog template's tests run in CI (2026-10-03): `talos-catalog-tests` includes every `module-templates/*/template.rs` that has a `#[cfg(test)]` module and runs it against `talos-module-testkit`, a native stand-in for the host bindings (`make test-templates`). Write the logic so a test can drive it — take the HTTP call as a closure, or set responses, memory, secrets and the clock through `talos_module_testkit::host` — and add any crate the template declares to `talos-catalog-tests/Cargo.toml`. See `docs/module-testing.md`.
- A catalog template that reads a response carries the run it was measured on (2026-10-03): `module-templates/<slug>/fixtures/http.json` (made-up data only), and a `recommended_fuel` in `talos.json`. `make check-catalog-fuel` builds the template through the production compile path, runs it against the recording in the worker runtime and fails above 80% of the declared limit; CI runs it, and `template-publish.yml` refuses to publish without a green `quality.yml` for the commit. A module moves from the authoring lane into the catalog with `scripts/promote-module.py`, which refuses per-user secret paths and identifiers. See `docs/module-promotion.md`.
- An action in a composed message is an action link (2026-10-04): the compose module returns `__action_links__: [{id, target, label, payload, fallback?}]` and writes `talos-action:<id>` where each link belongs; an `action_links` system node between compose and send mints them. The node's `targets` (author-written) are the only workflows a link may start. Do not mint capability URLs any other way, and do not make a GET act. See `docs/action-links.md`.
- A phone notification is composed as a service-neutral `notification` object and delivered by a `notify-*` adapter (2026-10-04, `docs/notification-contract.md`); changing service is swapping the send node's module. Do not put a service's vocabulary (a topic, an entity id, a device name) in a compose module or in stored memory, and do not edit one adapter's contract block alone: `talos-catalog-tests/tests/notification_contract.rs` holds the copies byte-identical. The same applies to any outbound service that may be replaced: a neutral shape, one adapter per service.
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
**Current measurement, 2026-09-26** (the paragraph above is the May figure, kept byte-identical): 148 workspace members; `controller/src/main.rs` + `controller/src/bootstrap/` are ~15.3k lines (`bootstrap/background.rs` alone ~6.6k), so "the bin is ~7.3k LoC" no longer holds. Derive these from `cargo metadata` / `wc -l` rather than trusting a figure here.

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
- **A test whose meaning depends on row security sets `TALOS_RLS_SET_ROLE` itself** (2026-10-02). The controller harness loads a developer `.env`, so local runs may enforce row security while CI (no `.env`) does not, and the switch is read once per process — one setting per test binary. Under `talos_app` a table's policy can hide a row before a statement's own ownership predicate is consulted, so pin that predicate in a binary that sets the switch OFF (`secret_delete_predicate_tests`).
- **Mutation testing is for security gates, not every change** (2026-09-25). Mutation-prove a change — apply the mutation, show the guarding test fail, revert, show it pass — when it guards tenancy, crypto, authentication/authorization, a write ceiling or an egress control: there a guard that passes its own mutation is a vulnerability. Elsewhere a test that fails on the pre-fix tree is enough, and a package record need not list mutations.

## Pre-deploy validation
- **`make lint` enforces structural rules** via `scripts/lint-structural.sh`. 97 checks today (`bash scripts/lint-structural.sh --count` prints the live number, and check 54 fails the lint if this sentence's count goes stale), each tied to a specific past regression so it catches at PR-time the class of bug that survives `cargo check` cleanly but breaks at CI or request time. Each check's SPECIFICATION — rule, scope, opt-out marker, measured precision, stated limits — is the comment block above it in the script, which is authoritative. The one-line index is the "Structural lint checks" subsection of `docs/engineering-log/DECISIONS.md`; the long entries this list carried until 2026-09-25 are archived verbatim in `docs/engineering-log/structural-lint-checks.md`. Checks 29, 53, 63 and 78 are enforced by CLIPPY (`clippy.toml` `disallowed-methods`, which resolves the call by type, so an alias or a UFCS call cannot hide one); their structural checks verify that config and where each sanctioned `// disallowed-method: <path> — <reason>` + `#[allow(clippy::disallowed_methods)]` sits. Adding a check: its comment block in the script, a line in the index.

- **Adding or deleting a test file needs no CI edit.** Both runners DISCOVER their binaries through `scripts/ci_test_targets.py`: a controller binary is classified by its harness (`mod common;` → the migrated-template DB, `mod test_helpers;` → testcontainers), any other binary that needs a service declares `// ci-store: <migrated|selfcontained|redis|services>`, one that must not run carries `// ci-ungated: <reason>`, and the rest run in the DB-free unit job. A binary that reads a `TALOS_TEST_*` variable with no marker is REFUSED (check 64) — defaulting it into the DB-free job would let it early-return green. Until 2026-09-25 each runner named its binaries by hand, every test-adding PR appended to the same lines, and deleting a test file broke CI with `no test target named <name>` (PR #567).
- **A registered Prometheus metric with zero increment sites is DEAD — an alert on it silently never fires.** `talos_workflow_executions_total` was registered in `talos-metrics` but never incremented anywhere, so the failure-rate alert built on it would never have fired (found + fixed 2026-07-24: wired it at the `mark_execution_completed`/`_failed` chokepoints in both repo crates, counted only on a real row transition). When adding an alert, confirm the metric has a live `.with_label_values(&[…]).inc()` (or `.inc()`) call site — not just a `CounterVec::new` + `registry.register`. Now enforced by structural lint **check 58**.
- **In PromQL, ABSENT and ZERO are different, and every common alert idiom (`== 0`, `< N`, `rate(...) == 0`, `a / (a+b)`) reads absent as "no match".** So a detector can be silenced by exactly the condition it detects: `NoWASMExecutions: rate(wasm_executions_total[30m]) == 0` could only fire on a worker that HAD executed and then stopped — never on the cold-dead case, which is the one that matters (found live 2026-08-02, alongside the same shape in `TalosBackupRestoreDrillFailed`, where a drill that had never run made "no successful drill in 14+ days" unfireable). Fix it on BOTH sides. **Producer:** a `CounterVec` emits nothing until a label set is touched and an OTEL instrument emits nothing until its first measurement, so pre-seed at 0 — but ONLY closed, compile-time-known label combinations that a live call site actually writes (seeding a combination nothing increments implies a wired signal that does not exist, and any caller-derived label value is an unbounded-cardinality DoS surface). **Consumer:** add an `absent(x) or …` arm where the absent series is one Talos itself is supposed to produce — and NOT where absence legitimately means "not applicable" (`vault_core_unsealed` on a cluster without Vault, `kube_*` without kube-state-metrics, `up` for a job check 65(a) already gates). An absent arm must keep the alert's existing severity. **`up == 1` certifies reachability, not production**: the meta-detector for "target green, producing nothing" is `WASMMetricsPipelineDead`, and it is kept off a permanently-red state by being gated on the target being up AND on the producer-side seeding — a permanently-firing alert trains operators to ignore red, which is the same defect. `observability/alerts_test.yml` drives these transitions through `promtool test rules`; it is NOT CI-wired (no Prometheus toolchain on the runners) and says so in its own header.
- **The local gates are fast; CI is the authority** (2026-09-25). pre-commit: the secret/migration checks and `cargo check --all-targets` of the crates you STAGED (not the workspace). pre-push: `make lint` (rustfmt + the structural lints + offline cargo-deny) and `make lint-frontend` (eslint + prettier). Workspace clippy (`-D warnings`, all targets) and vitest run in `quality.yml` on every PR and in the merge queue; `make lint-full` / `TALOS_PREPUSH_FULL=1 git push` runs them locally, worth it before the push you expect to be a PR's last. Recurring clippy surprises: `trivially_copy_pass_by_ref` on serde `skip_serializing_if(&T)` helpers (allow it — serde mandates the ref), needless late-init (`let x; if … {x=…}` → `let x = if …`), and ref-to-ref on `Option<&T>` params.
- **`scripts/smoke.sh` end-to-end probe.** Runs every public path against a deployed cluster (`/health`, `/auth/csrf` cookie seeding, `/graphql` with full CSRF round-trip, `/ws` handshake, `/mcp`); optional Phase-B encryption write→read round-trip with `SMOKE_AGENT_TOKEN` + `SMOKE_ACTOR_ID`. `deploy/k3s/install.sh` invokes it as §9.1 at the tail of every deploy — a failed smoke warns but doesn't abort install. Run manually any time with `make smoke BASE_URL=https://…`.
- **When introducing a new top-level path on the controller**: add a matching `location` block to the chart's nginx ConfigMap, OR mark the route `// no-nginx-route: <reason>` (kubelet probes, in-cluster scrape, etc.). The lint check 2 catches drift either way; the smoke test fails fast in production if the path is supposed to be public but nginx routes it to the SPA.

## Image publishing
- **CI OIDC publish is canonical** (Jul-2026): `gh workflow run main-publish.yml --ref main`. The workflow's `ci-gate` job REQUIRES a green `quality.yml` run for the exact SHA (bypass: `skip_ci_check` dispatch input), builds all three images for linux/amd64 (frontend from `frontend/` context — repo-root context breaks its Dockerfile), pushes via `GITHUB_TOKEN`, cosign-signs each digest with the **workflow's OIDC identity** (Fulcio keyless — NOT any operator's personal identity, killing the per-operator regexp-widening problem), and emits the `TALOS_*_DIGEST` block in the run summary. Clusters pin `^https://github\.com/OWNER/talos/\.github/workflows/main-publish\.yml@` (trailing `@` load-bearing, same rule as template-publish). Runbook: `docs/second-operator-publish-runbook.md`. The local script below is the documented fallback.
- **Auto-triggers stay OFF** (May-2026 decision): the four image/publish workflow files (`ci.yml`, `release.yml`, `main-publish.yml`, `template-publish.yml`) are gated to `workflow_dispatch:` only — every publish is an explicit act. The `push:` / `pull_request:` / `tags:` blocks are commented out, not deleted.
- **Exception — `quality.yml` IS auto-triggered** (Jun-2026): the heavy correctness gates too slow/networked for the pre-push hook — full Rust test suite, the env-gated **integration** tests (`make test-integration`: RLS isolation, crash-recovery, …) that `cargo nextest` alone skips, the networked RUSTSEC advisory scan (`make audit`), and a frontend lint+test backstop — run on `pull_request` to main, in the **merge queue** (`merge_group`), nightly (`schedule`) and on `workflow_dispatch`, each job gated by the paths a change touches (`scripts/ci-changed-areas.sh`) behind ONE required check, `Quality gate`; the integration suite runs as three shards. See `docs/ci.md`. It deliberately excludes the expensive image-build jobs (those stay in `ci.yml`). This is the unbypassable backstop for the gates the (opt-in) pre-push hook can't cover; it exists because the gated integration suite silently rotted (a security RLS suite sat red on main for days — PR #181/#182).
- **`scripts/publish-images.sh`** is the local FALLBACK build path (was canonical until Jul-2026). Mirrors `main-publish.yml`'s contract: builds via `docker compose build controller worker` plus a separate `docker build -f frontend/Dockerfile` (the compose file points the frontend at `Dockerfile.dev` for local-dev), pushes `:main-<sha>` (+ `:main-latest`) to `ghcr.io/<owner>/talos-*`, captures digests via `docker inspect`. Flags: `--no-push`, `--no-sign` (signing default ON — see below), `--allow-dirty`, `--skip-ci-check`, `--service NAME`, `--platform linux/amd64` (default, mandatory on Apple Silicon → x86_64 deploys), `--update-env PATH`. Emits a copy-pasteable `TALOS_*_DIGEST=…` block for `/etc/talos/install.env`.
- **Publish gate (2026-07-01)**: pushing requires (a) a **clean tree** (dirty publishes REFUSED; `--allow-dirty` for debugging, tags suffixed `-dirty`) and (b) a **green `quality.yml` run for HEAD**, verified via `gh run list --commit`. The MERGE QUEUE supplies that run: the commit `merge_group` tests is the commit that lands on main, so `gh run list --commit` finds it. (Until 2026-09-25 a `push: branches: [main]` trigger re-ran the whole suite on every merge for the same purpose; the next merge cancelled it two times in five, measured 2026-09-25.) Bypass is explicit: `--skip-ci-check` / `TALOS_PUBLISH_SKIP_CI_CHECK=1`.
- **Signing is DEFAULT-ON** (flipped 2026-07-01; provenance is the default act, skipping it the deliberate one — the batched single-OAuth-tab flow removed the cost that justified default-OFF). Opt out with `--no-sign` or `TALOS_PUBLISH_SIGN=0`. The script BATCHES all images into a single `cosign sign --yes` invocation — one browser tab, one OAuth token, three Fulcio cert issues. Fallback to per-image loop only if the batched call fails (old cosign versions, etc.).
- **Signing identity binding**: CI-published images carry the WORKFLOW URI identity (issuer `https://token.actions.githubusercontent.com`) — the stable, operator-independent pin clusters should prefer. Locally-signed images instead carry the operator's GitHub OAuth identity (issuer `https://github.com/login/oauth`), NOT a workflow URI; production clusters with Sigstore enforcement enabled (`TALOS_SIGSTORE_REQUIRED=true`) admitting locally-signed images need their identity regexp widened to the operator's email pattern PER HUMAN — the exact problem the CI path removes. The chart-level signing contract is otherwise identical (cosign + Fulcio + Rekor public-log entry).
- **Secret rotation auto-bounce (MCP-1231)**: every dependent pod template (controller / worker / NATS / Neo4j / postgres) carries a `checksum/<secret>-data` annotation rendered from `helm lookup` over the live secret content. When install.sh rotates the bootstrap / postgres-credentials / neo4j-auth secrets out of band, the NEXT `helm upgrade` notices the data hash changed and rolls the consumer pods automatically. Pre-MCP-1231, every rotation required manual `kubectl delete pod talos-{nats,neo4j,postgres}-0` rituals — observed three days in a row during the in-cluster Postgres rollout.
- **Dirty-tree publishes are refused** by default (see publish gate above). With `--allow-dirty` the tags are suffixed `-dirty` so they can never be confused with a clean-main image. Don't deploy `-dirty` builds to production.
- **CI gates** (lint, test, structural lint) run locally via `make lint-full` and `cargo test --workspace`. Run `make hooks` once per clone to install the git hooks (`core.hooksPath=.githooks`); they run the FAST gates (see "The local gates are fast" under Pre-deploy validation) and `quality.yml` runs the rest. Emergency bypass: `git push --no-verify`. Still run `cargo test --workspace` + `make lint-full` before `bash scripts/publish-images.sh`.

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
- **A module row runs compiled bytes or a registry artifact, never both** (2026-10-03). A row that names an artifact (`oci_url`) holds no bytes and no source; the worker pulls and verifies it. "Can this row run" is bytes OR `oci_url` — a listing or resolver that asks only about bytes hides every registry module. An installed copy is written by `ModuleRepository::install_catalog_copy` (`InstalledArtifact::{Compiled, Registry}`), which replaces the other kind in the same statement; a registry-reference copy is not hot-updated, and an in-process run asks `WasmModule::in_process_bytes()` first. In registry mode `list_module_catalog` and `install_module_from_catalog` read the shared registry rows, not the image's `module-templates/`. Decided 2026-10-04 (`docs/engineering-log/packages/2026-10-04-module-lane-decisions.md`): a copy keeps the reference it was installed with (not a digest pin), hot update of a reference copy is refused (not a detach), and there is no boot gate requiring a registry in production — do not re-propose these without new facts.
- **Sigstore identity regexp pins to the workflow URL.** Format: `^https://github\\.com/OWNER/talos/\\.github/workflows/template-publish\\.yml@`. Without the trailing `@`, an attacker who creates a fork named `template-publish.yml-evil.yml` could match. The OIDC issuer pin (`https://token.actions.githubusercontent.com`) restricts to GitHub Actions tokens specifically. Cosign is bundled in the worker Dockerfile at a pinned version so verification doesn't depend on operator's PATH or apt repository state.
- **A shared catalog row has ONE manifest parser and ONE writer** (2026-10-03): `talos_registry::reconcile::CatalogManifest::parse` and `upsert_catalog_template_by_slug`, used by both the disk seed and the registry sync with a `CatalogSource` saying where the code comes from. A new field a catalog row stores goes into `CatalogManifest`; do not parse `talos.json` or write a `kind = 'catalog'` row anywhere else. A manifest must declare its `capability_world` — it is never defaulted.

## HTTP middleware & router rules
- **`cors_middleware` short-circuits ALL `OPTIONS` requests** (`controller/src/main.rs::cors_middleware`). It builds an empty 200 response and returns immediately, never calling `next.run`. Consequence: an `OPTIONS` preflight cannot trigger ANY downstream middleware (including `csrf_protection_graphql`). Don't try to seed cookies or run validation logic via OPTIONS — pick a real GET endpoint.
- **`tower_cookies::CookieManagerLayer` on a sub-router merged AFTER the outer `CookieManagerLayer` is unreliable.** When a sub-router is `.merge`d into the parent app and you re-add `CookieManagerLayer + cookie-modifying middleware` inside that sub-router, `Set-Cookie` headers can fail to appear in the response (root cause not pinned down — likely a layer-ordering interaction with axum's response mapping). For cookie writes on routes that bypass the main cookie layer, build the `Set-Cookie` header by hand in the handler. See `seed_csrf_handler` for the reference pattern.
- **Probe and exempt routes need their own Extension layers.** `probe_routes` is merged AFTER the rate-limit layers (so kubelet probes can't be 429'd). The Extension layers (`db_pool`, `redis_client`, `nats_client`) attached to the main app DON'T propagate to merged sub-routers — re-attach them on the sub-router or the handlers panic with "Extension not found". The `mcp_router` follows the same pattern.
- **Per-IP rate-limit identification MUST use RFC 7239 right-to-left X-Forwarded-For walk** (`rate_limit::extract_client_ip`). Reading the leftmost entry is exploitable: any client behind a trusted proxy can prepend a fake IP and the server attributes their requests to it. The walk skips trusted-proxy entries from the right; the first untrusted entry is the real client.
- **Probe paths are exempt from rate limiting two ways**: (1) architectural — `probe_routes` merged after rate-limit layers; (2) defence in depth — `is_rate_limit_exempt_path()` early-returns from `rate_limit_middleware` and `global_rate_limit_middleware`. With Traefik on `externalTrafficPolicy: Cluster`, kube-proxy SNATs all external traffic to a single node IP, so without the exemption a busy site evicts kubelet probes from the per-IP bucket → pod marked NotReady → 502 cascade.
- **Helm controller probes use `/live` and `/ready`, not `/health`.** `/live` is a trivial process-alive check (no DB/Redis/NATS calls) — a Postgres hiccup can't restart the pod. `/ready` returns 503 only when Postgres is down (Redis/NATS report degraded but still 200). `/health` is the user-facing combined check, kept for the frontend's `seedCsrfCookie` and ad-hoc curl.
- **WebSocket handlers MUST extract Origin from the request HeaderMap** and pass it into `ws_auth::handle_websocket_auth` — passing `None` makes EVERY WS connection fail in production with "missing Origin header" because `is_production()` requires the header. The handshake still returns `101` (the upgrade succeeds), then the socket is immediately closed by `handle_websocket_auth`, which the browser surfaces as `WebSocket connection failed:` with no detail.
