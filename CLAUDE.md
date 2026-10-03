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

**2026-10-03: the package record moved out, by operator decision.** This narrows
the sentence above rather than repeating the age-based sweep it rejects: what moved
is one CLOSED block of self-contained one-bullet-per-package digests, whole and
verbatim, to `docs/engineering-log/2026-10-03-package-record.md`, with one title line
per package left in the last subsection of this section. Measured: 458,697 → about
249,000 bytes (46%), roughly 52k tokens off every session start and every re-read
after a context compaction. The cost, stated: those packages' decisions are no longer
in context. The rule that replaces having them loaded: **before changing an area a
title names, read its bullet in that file.** The class digests below are NOT moved.

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

**Deliberately NOT done / recorded.** (A post-auth DLQ enqueue site was listed here and is CLOSED — #796's `capture_post_auth_drop` stamps every below-the-gate dispatch failure `authenticated: true`; the pre-auth breaker/rate-limit drops stay un-replayable by design.) (TOTP/OTLP AAD domain separation and the three v3 writers on org data were listed here and are CLOSED by #797 — package C above. `frontend/src/generated/*` was listed as not regenerated and is CLOSED: `quality.yml` runs `npm run codegen && git diff --exit-code` on every PR, so a stale snapshot cannot merge.) `set_actor_llm_tier_ceiling` loosening on a no-2FA credential (product call); webhook POST retry default 3 (pinned contract); Unicode look-alike delimiters.

### The package record, 2026-09-10 to 2026-09-25 → [`2026-10-03-package-record.md`](docs/engineering-log/2026-10-03-package-record.md)

**The package record (2026-09-10 → 2026-09-25) is a title index here; the record itself is in [`2026-10-03-package-record.md`](docs/engineering-log/2026-10-03-package-record.md).** Each line below is one package's title. Its decisions, `deliberately NOT`s, measured populations and stated limits are the bullet of the same title in that file, and its narrative is in the review archive. They were moved out on 2026-10-03: at 228 KB they were half of this file. **Before changing an area a title names, read its bullet** (`grep -n '<title words>' docs/engineering-log/2026-10-03-package-record.md`): the bullet is what says a lint was measured and rejected, or a behaviour is deliberate. Closed to new lines since 2026-09-25 — a package writes its own file under `docs/engineering-log/packages/`.

* C, 2026-09-10, follow-up PR — the last three GLOBAL-DEK writers of org-scoped data (`workflow_executions.output_data_enc` via the workflow/actor repositories; `webhook_triggers.signing_secret_enc` via MCP `create_webhook`) now take v4-or-global / v4-for-user with the RETURNED format bound.
* F, 2026-09-10, follow-up PR — worker NATS credential: publish DENY-list, closed SUBSCRIBE set.
* 2026-09-10, follow-up PR — `set_workflow_priority` is a LABEL; nothing orders dispatch by it.
* 2026-09-11 — the installer applies RFC 0010 worker trust by default in four loss-free phases.
* K, 2026-09-11 — `worker_identities.supports_sealing` derived, two dead crates deleted.
* L, 2026-09-11 — the chart REFUSES the Postgres connection arithmetic.
* M, 2026-09-11 — the scheduler's startup ceiling (`SCHEDULER_STARTUP_MAX_CONCURRENT`, default 4) keyed on process age alone; a clock catch-up after a host suspend is now its own phase via `talos_scheduler::classify_dispatch_phase(first_poll, max_overdue_secs)`.
* S, 2026-09-11 — the crypto-orphan blind-detector alert kept a 60 s cadence after #794 made the sweep hourly.
* T, 2026-09-11 — promtool fixtures run in CI: `make test-alert-rules` + the `alert-rules` job in `quality.yml`.
* V, 2026-09-11 — `admin_event_log` gained an operator-facing reader; never-written `audit_events` DROPPED.
* W, 2026-09-12 — `list_admin_events` + per-resource `admin_events` blocks reach the unreachable audit rows.
* X, 2026-09-12 — `DatasetService::assign_splits` no longer rewrites rows to the value they hold.
* Y, 2026-09-12 — eleven dead tables dropped, one live audit trail exported.
* AA, 2026-09-12 — `talos-node-cache` / `node_result_cache` DELETED (package K's rule).
* AC, 2026-09-12 — forty-five indexes redundant by DEFINITION dropped.
* AD, 2026-09-12 — RLS (migration `20260912130000`) on the three unpoliced tenant tables read on a scoped connection; the other 34 RECORDED, not gated.
* AE, 2026-09-12 — eleven RLS policies re-keyed off the `OR org_id IS NULL` transition arm (migration `20260912140000`).
* AF, 2026-09-12 — the dead `secrets` org-autostamp trigger is DROPPED, not re-keyed.
* AG, 2026-09-12 — every `workflow_executions` terminal-status write records its outcome through ONE home.
* AH, 2026-09-12 — the archive's status CHECK now equals the live set.
* AI, 2026-09-12 — actor context left the workflow repository.
* AJ, 2026-09-12 — two `docs/configuration-reference.md` security rows rewritten from their readers.
* AK, 2026-09-12 — `docs/configuration-reference.md`'s Component column said `both` for 108 worker-unreadable variables (`TALOS_MASTER_KEY`, `JWT_SECRET`, `VAULT_ADDR`, `NEO4J_PASSWORD` …); check 89 derives it from `cargo tree`.
* AL, 2026-09-12 — 24 of 107 🔒 config-reference rows corrected against their readers.
* AM, 2026-09-12 — a production boot REFUSES a requested Ed25519 scheme or claim-based sealing without a usable signer.
* AN, 2026-09-12 — `talos_config::bool_env` / `bool_env_or_default` (`true|1|yes|on`, `false|0|no|off`) is the one boolean env vocabulary; check 90 (24 → 0).
* AO, 2026-09-12 — the `lint` and `clippy` jobs moved from `ci.yml` into `quality.yml` (one home).
* AP, 2026-09-12 — Google push refusals and JWK refreshes have series; a backoff window is reported as a window.
* AQ, 2026-09-13 — check 2 graduated from `⚠` + exit 0 to failing, at zero.
* AR, 2026-09-13 — `SigstorePolicy` has ONE home.
* AS, 2026-09-13 — both chart Deployments render `TALOS_SIGSTORE_REQUIRED` / `_IDENTITY_REGEXP` / `_OIDC_ISSUER` from ONE values block.
* AT, 2026-09-13 — 25 env vars production code reads had no row in `docs/configuration-reference.md`; all documented; check 89 gained leg (e), the reverse arm (25 → 0).
* AU, 2026-09-13 — every vault key path in a log line renders through ONE shared redactor.
* AV, 2026-09-13 — `TalosAuditChainUnverifiable` split on the code's own partition.
* AW, 2026-09-13 — the `AUDIT_LEDGER` JetStream stream is bounded to 30 days, in place.
* AX, 2026-09-13 — MCP agent-token auth refusals are counted and logged.
* AY, 2026-09-14 — the engine's OAuth repair re-dispatched one `job_id` at attempt 0, minting false tamper verdicts.
* AZ, 2026-09-14 — an unchanged ML example re-append no longer rewrites rows or touches `ml_datasets.updated_at`, so hourly re-distills stop minting `ml_model_versions`.
* BA, 2026-09-14 — the Vault KEK token is renewed; production REFUSES an `Expiring` one.
* BB, 2026-09-14 — `tool_search`'s `TOOL_GROUPS` and 19 prose sites named tools that do not exist.
* BC, 2026-09-14 — LaunchAgent PATHs are DERIVED from where the installing shell resolves each tool.
* BD, 2026-09-14 — `execution_cost_rollup` joins the tier-four reaper on its own 90-day clock.
* BE, 2026-09-14 — the demoted `last_child_activity_at` proxy (+ `DORMANT_CHILD_ACTIVITY_CAVEAT`) removed eight days early.
* BF, 2026-09-14 — the execution pause (`system_settings` row `execution_paused`) could never be set and was read by almost nothing; ONE home now, leaf crate `talos-execution-pause`.
* BG, 2026-09-14 — the execution pause gates its remaining seven start paths, defer-don't-drop.
* BH, 2026-09-15 — an approval decision on `execution_approvals` is final.
* BI, 2026-09-15 — the disk preflight prints reclaimable figures beside its remedies; the `builder prune` flag has ONE home.
* BJ, 2026-09-15 — a post-pause backlog is logged as a pause, not missed polls.
* BK, 2026-09-15 — check 88's PREPARE probe refuses a run that never reached the database.
* BL, 2026-09-15 — the WORM ledger records host-initiated credential use.
* BM, 2026-09-15 — one shared clone-actor service behind MCP `clone_actor` and GraphQL `cloneActor`.
* BN, 2026-09-15 — the never-enforced daily fuel budget is DELETED.
* BO, 2026-09-15 — `talos-tenancy`'s quota placeholders DELETED.
* BP, 2026-09-15 — `talos-secrets-rotation`, a never-constructed crate a SOC 2 control cited, DELETED.
* BQ, 2026-09-15 — `talos_audit_ledger::verify_execution_chain` (the ONE production verifier call) now runs `verify_chain_anchored`, shipped 2026-09-06 with no production caller; `verify_chain` cannot see a deleted tail.
* BR, 2026-09-16 — the capability-grant CHECK admitted dead worlds and refused `llm-node` / `agent-node`; the ceiling read has one home.
* BS, 2026-09-16 — the audit sweep's summary verdict has ONE home.
* BT, 2026-09-16 — the web UI's actor-ceiling forms serve the backend lattice, not a hard-coded ladder.
* BU, 2026-09-16 — auditor-facing evidence citations and the capability model rewritten from the code.
* BV, 2026-09-16 — auditor-facing docs corrected against code at `839069cf`.
* BW, 2026-09-16 — MCP-agent registration and revocation are atomic with their `admin_event_log` record.
* BX, 2026-09-16 — 16 unpinned container images pinned by digest; check 93 gates it.
* BY, 2026-09-16 — the chart's Vault is re-unsealed by a sidecar and keeps no standing root token.
* BZ, 2026-09-16 — two always-500 routes deleted; runtime guard + route crawl added.
* CA, 2026-09-17 — `TALOS_COMPILATION_CONTAINER=false` no longer bypasses the host-fallback acknowledgement.
* CB, 2026-09-17 — eight boolean env vars parsed outside `talos_config::bool_env` / `bool_env_or_default` now route through it; check 90 grew two legs (no new number).
* CC, 2026-09-17 — approval-policy triggers with no detector are REFUSED at creation.
* CD, 2026-09-17 — `on_budget_exceeded = alert` raises an ops alert; lifetime-cap decode fixed.
* CE, 2026-09-17 — `rotateOrgDek(orgId)` rotates AND re-keys a per-org DEK, platform admin only.
* CJ, 2026-09-17 — a `module_executions` output is sealed under the key and format the row ALREADY names (operator decision: one key per row).
* CF, 2026-09-17 — the "per-process 2FA lockout" finding is REFUTED for production; the Redis path is now driven.
* CG, 2026-09-17 — migration `20260917130000`: a `BEFORE TRUNCATE … FOR EACH STATEMENT` guard on `auth_audit_log` / `secret_audit_log` / `admin_event_log`, and BOTH triggers on `schema_audit_log` (2 280 rows), `oauth_audit_log` (1), `gmail_integration_audit_log`, `slack_integration_audit_log` (0 each).
* CH, 2026-09-17 — `admin_event_log` has ONE writer; check 94.
* CI, 2026-09-17 — the GitHub webhook dedup window is 24 h and has ONE home.
* CK, 2026-09-18 — every execution start runs ONE shared in-transaction actor-budget check.
* CL, 2026-09-18 — the per-org output sweep and `dekMigrationStatus` cover `workflow_executions_archive`.
* CM, 2026-09-18 — a Google push stream that stops is sayable: `talos_google_push_accepted_total` + `TalosGooglePushSilent`.
* CN, 2026-09-18 — the two budget pre-checks share one body and one set of count statements.
* CO, 2026-09-18 — `require_2fa` passed on a password alone (`is_2fa_verified = !totp_enabled`; API keys minted true); sessions now record what they PROVED and a privileged tier uses `require_second_factor`.
* CP, 2026-09-18 — the 2FA QR code renders.
* CQ, 2026-09-18 — the public OAuth no-password sentinel opened accounts; unusable hashes have one home.
* CR, 2026-09-18 — `changePassword` mutation + Settings form; change, session revocation and audit row are ONE transaction.
* CS, 2026-09-18 — credential and privilege-grant changes record to `admin_event_log` in the same transaction.
* CT, 2026-09-19 — every privilege change records its `admin_event_log` row in the change's own transaction.
* CU, 2026-09-19 — controller signed-RPC subscribers queue-subscribe in ONE group.
* CV, 2026-09-20 — the `wasm.log.*` relay moved to library crate `talos-wasm-log-relay` with TWO supervised subscriptions: persist (queue group `subjects::CONTROLLER_WASM_LOG_QUEUE_GROUP` = `talos-controller-wasm-log`) and broadcast (plain, `BackgroundTask::WasmLogBroadcaster`).
* CW, 2026-09-20 — a fleet lease for periodic loops; both SLA monitors take it.
* CX, 2026-09-20 — Google Calendar watch create/renew under a fleet advisory lock, re-read inside it.
* CY, 2026-09-21 — the five LLM/ML loops take the fleet lease: once per interval, across restarts.
* CZ, 2026-09-21 — `complete_execution_from_worker` seals module output like its two siblings.
* DA, 2026-09-21 — the stale sweep's failure writer is in the finalizer home and counts.
* DB, 2026-09-21 — the `talos.results.*` observer (the ONLY finalizer for reply-inbox-less dispatches: Gmail/GCal/GCP module-bound pushes, webhook DLQ replay) moved to library crate `talos-job-result-observer` and queue-subscribes in `subjects::CONTROLLER_RESULTS_QUEUE_GROUP` (`talos-controller-results`).
* DC, 2026-09-21 — SIGTERM drains in-flight runs for `RUN_DRAIN_GRACE` = 120 s, then fails ONLY this process's leftovers.
* DD, 2026-09-21 — `cleanup_workflows` deletes through the guarded statement.
* DE, 2026-09-21 — GraphQL `deleteWorkflow` gains the child-reference guard.
* DF, 2026-09-21 — every workflow delete records one `admin_event_log` row naming what it removed, transactionally.
* DG, 2026-09-21 — every module delete records what it removed, in its own transaction.
* DH, 2026-09-21 — five terminal `workflow_executions` writers the counter never saw moved into `talos-execution-finalizer`; check 46 gained leg 46b.
* DI, 2026-09-21 — no `admin_event_log` writer records after its change; `spawn_log_admin_event` DELETED.
* DJ, 2026-09-21 — refresh-token reuse detection has series and alerts.
* DK, 2026-09-22 — a model read that did not ANSWER is no longer "Model not found"; `classify_model_lookup` is ONE home.
* DL, 2026-09-22 — SQL-shaped lint checks read statements through ONE statement-aware lexer.
* DM, 2026-09-22 — advisory-DB age: one home, three gauges, three alerts.
* DN, 2026-09-22 — the whole-codebase-review section compressed to decisions, with the losslessness checker finally wired as a gate.
* DO, 2026-09-22 — CI's clippy covers every target; 107 test-target warning sites in 55 files burned to zero.
* DP, 2026-09-22 — the frontend's session refresh has ONE home.
* DQ, 2026-09-22 — check 42 reads the statement, not a 16-line window.
* DS, 2026-09-22 — a request already on the wire when a refresh settles retries with the fresh cookie instead of refreshing again.
* DT, 2026-09-22 — 2FA login had never worked: the frontend's `verifyTwoFactor` document named an input type the schema does not have.
* DU, 2026-09-22 — the WebSocket lane has series: `talos_ws_handshakes_total{outcome}`, `talos_ws_session_ends_total{reason}`, `talos_ws_operations_total{outcome}`, `talos_ws_active_sessions`.
* DW, 2026-09-22 — an anonymous page load no longer spends two round trips learning it is anonymous.
* DV, 2026-09-22 — every GraphQL subscription rides ONE socket per page; the server lane multiplexes by id.
* DX, 2026-09-23 — a job that was never executed is no longer judged as a module error.
* DY, 2026-09-23 — the GraphQL privileged gate was the last bearer surface with no series.
* DZ, 2026-09-23 — caller-supplied module source was silently rewritten, and only on two of six paths.
* EA, 2026-09-23 — two instruments that overstated what they observed, and one claimed defect WITHDRAWN on measurement.
* EB, 2026-09-23 — the "flaky integration test class" was measured and is NOT a class; one home for the bounded wait instead.
* EC, 2026-09-23 — two tools rejected the name they had just handed the caller back.
* ED, 2026-09-23 — a Plaid integration, and the SHAPE was decided by an existing control rather than chosen.
* EE, 2026-09-23 — `vault://` substitution reached headers only, so an API that takes its credential in the JSON BODY was unbuildable as a module. The claim that widening it would be a security regression is WITHDRAWN — it conflated PLACEMENT with DISCLOSURE.
* EF, 2026-09-23 — three documented env vars an operator had just set reached nothing; check 97.
* EG, 2026-09-23 — linking a Plaid item, controller-side, with the credential's only destination the vault; and the KEK resolution gets ONE home.
* EH, 2026-09-23 — the two SANDBOX surfaces handed a guest the plaintext the ENGINE never gives it; three divergences, one direction.
* EI, 2026-09-23 — the write ceiling's HTTP and GraphQL legs INFER "mutating" from the VERB, and no operator-facing surface said so.
* EJ, 2026-09-24 — `allowed_methods` was the one module grant where declaring nothing granted everything; ONE home now, and a fifth gate that had none.
* EK, 2026-09-24 — EJ made an empty `allowed_methods` deny, and five carriers were still writing one; `run_sandbox` could not issue a single HTTP request for nine hours.
* EL, 2026-09-24 — `max_write_ceiling` splits into two axes, and the partition is PROVABILITY rather than destination.
* EM, 2026-09-24 — EL's axis was a NO-OP: the worker dropped the override on arrival, and four operator surfaces still advised the broad grant.
* EN, 2026-09-24 — `allowed_secrets` has TWO vocabularies and four operator surfaces taught the one that delivers nothing.
* EO, 2026-09-24 — a LaunchAgent PATH derived from the installing shell, and the off-host drill leg that could never have run.
* EP, 2026-09-24 — the post-DN package bullets drifted 3.6× past the ceiling DN left, and the discipline that let them is now written down.
* EQ, 2026-09-24 — header substitution reached every egress surface; BODY substitution reached one of four.
* ER, 2026-09-25 — four lint-check entries compressed to specification only; the block is now CLOSED and EP's estimate is REFUTED.
* ES, 2026-09-25 — an API key could mint a verified session; bcrypt ran on the runtime thread; the capability bootstrap re-armed.
* ES, 2026-09-25 — an unreadable watch lookup ACKED the push, discarding a delivery the transport would have redelivered; the reference integration had it right and both copies inverted it.
* ET, 2026-09-25 — integration connect flows bind `state` to the browser; a GitHub App installation is claimed only with GitHub's proof of access and never moved off an active owner.
* ET, 2026-09-25 — EQ's `fetch_all` limit closed at the TYPE level; and four candidates measured and NOT changed.
* ET, 2026-09-25 — four privilege-ceiling / egress gaps from a 2026-09-25 review.
* EU, 2026-09-25 — four execution paths repeated side effects or skipped actor gates.
* EU, 2026-09-25 — three workflow-engine correctness defects from the 2026-09-25 review.
* EU, 2026-09-25 — four silent data-loss paths closed.
* EV, 2026-09-25 — six guest-reachable resource-exhaustion paths bounded.

### The lint checks' regression narratives → [`2026-09-25-lint-check-narratives.md`](docs/engineering-log/2026-09-25-lint-check-narratives.md)

**The class.** A lint check's CLAUDE.md entry carries two things: its
SPECIFICATION (the rule, the scope, the opt-out marker, every measured precision
number, the recorded decisions, the stated limits) and the regression STORY that
motivated it. The specification is why the entry lives in a file read at every
session start; the story is not. Four entries — **74** (report-side swallowed
reads and sub-leg 74b's `Readings` ledger), **88** (static sqlx statements that
must PREPARE), **83** (an explicit `updated_at = NOW()` overriding the trigger's
verdict) and **65** (the dev Prometheus that observed nothing of Talos) — were
compressed to specification only; their stories moved VERBATIM to the archive
file above. Measured: **45,560 → 20,993 bytes, a 54% cut, 24.6 KB off every
session start.**

**DECIDED: the block is now CLOSED for compression, and the estimate that opened
it is REFUTED.** Package EP recorded that the top twelve entries were 51% of the
186 KB block while a check's actual specification is "600–900 B", implying ~85 KB
recoverable. That estimate was taken from the MEDIAN entry (659 B) and does not
survive contact with the large ones, where the scope is a twenty-term name glob,
the precision is four separately-measured populations and the limits are five
enumerated evasions. Measured per entry, worst-first: 74 **56%**, 83 **62%**,
88 **51%**, 65 **45%** — then **79 at 27%** and **85 at 12%**, both of which are
two legs plus a sub-leg with their own numbers and limits, i.e. almost pure
specification. **79 and 85 are therefore deliberately NOT compressed**, and the
remaining 91 entries have a median of 659 B and are already at the specification
floor. So DN's original reason for leaving this block alone ("its inline
documentation IS each check's specification") holds better than EP's
re-measurement suggested; what EP got right is that the four largest carried
story worth moving, and that is now done.

**Stated limit.** What stayed is a judgement about which clause is specification
and which is story, made by the author of the compression. The archive keeps
every original byte-for-byte, so a clause cut in error is recoverable rather than
lost, and structural check 96 proves that mechanically against a pinned base.

### Structural lint checks → [`structural-lint-checks.md`](docs/engineering-log/structural-lint-checks.md)

**What moved, and why it is not the compression package ER declined.** The
numbered list under "Pre-deploy validation" held one long entry per check —
162 KB, 27% of this file, read at every session start — and it was a SECOND
copy of each check's specification: the comment block above the check in
`scripts/lint-structural.sh` is the one the lint runs beside, and the two had
drifted (two entries numbered 82, none for 84 or 97). The entries moved
VERBATIM, not compressed, so ER's "no further entry is compressed" stands; what
is retired is the duplicate. DN's "the inline documentation IS each check's
specification" is kept in the sense that matters: the inline documentation is
the script's.

**Also decided with it.** `scripts/check-engineering-log.py` now pins each
split's COMMIT beside its base and holds a split only to what IT removed.
Comparing every base with today's file had charged every later edit of a
line that existed in any base to the split — bumping "96 checks today" to
"97" failed check 96 until the old sentence was copied into an archive (four
such copies sit in the review archive). The newest split's commit is pinned
by the change after it.

**The index.** Rule, scope and limits of each: the script. `(clippy)` =
enforced by `clippy.toml`.


  1. actor_memory writes + value-column projections outside talos-memory/
  2. top-level controller routes vs nginx locations
  3. __actor_context__ injection key (no __agent_context__ regressions)
  4. SecretsManager::new(...) outside canonical wiring
  5. helm chart renders cleanly
  6. raw sqlx::query inside talos-mcp-handlers/
  7. cargo clippy --workspace --all-targets --no-deps -- -D warnings
  8. trigger_type column references against workflow_executions
  9. boolean-column drift against workflow_schedules / webhook_triggers
  10. discarded Result on an awaited call (raw sqlx everywhere; any callee in mcp-handlers)
  11. misleading-success Err-only outbound webhook fires
  12. caller-supplied limit clamp drift (.unwrap_or().min() shape)
  13. chart-wide labels under NetworkPolicy from:/to: selectors
  14. talos-api Err(async_graphql::Error::new) missing .extend_safe()
  15. graph_json writes via canonical chokepoint (MCP-1226/1227/1228/1229)
  16. wit/talos.wit ↔ module-templates/wit/talos.wit drift
  17. encrypted_secrets: Default::default() outside tests
  18. JobResult/.sign() in worker (must use sign_with_worker_id)
  19. worker must single-publish each JobResult (no dual NATS publish)
  20. every wasmtime WASM proposal must be explicitly opted in/out
  21. integer-cast wraparound (.as_u64().*as u32 / map(|i| i as i32))
  22. GraphQL queries with sibling mutations must have a scope gate
  23. encrypt_value()/decrypt_value_by_key() without AAD outside the secrets table
  24. inline control-char predicate in a write surface
  25. bare-pool queries on RLS tables in talos-api/src/schema
  26. in-flight status literal must include 'resuming'
  27. make_interval(<int arg> => $N) must cast $N::int
  28. OFFSET pagination needs a unique ORDER BY tiebreaker
  29. no bare engine.set_actor_id() outside the actor-application path  (clippy)
  30. no CONCURRENTLY in migrations (sqlx runs them in a transaction)
  31. outbound HTTP response bodies must be read through talos-http-body
  32. reqwest Client::builder() must set an explicit .redirect() policy
  33. capability-world ranking must use talos-capability-world, not a local re-impl
  34. actor_memory value_format reads must fail loud (MCP-S2 AAD dispatch)
  35. cargo fmt --all -- --check (rustfmt drift)
  36. cargo audit (RustSec dependency advisories)
  37. secret-holding structs must redact in Debug (no derive(Debug))
  38. allow_wasi_network grants must gate on max_llm_tier (tier-1 egress)
  39. workflow_executions status writes must carry a status guard
  40. SSRF-checked outbound URLs must use the shared safe HTTP client
  41. approval-gate token lookups must use token_hash, not the raw token
  42. org-pinned-table creates must run on a tenant-scoped tx
  43. controller test setup must use the isolated-DB harness, not init_pool()
  44. production in-transit TLS gates must fail closed (not warn)
  45. env-KEK in production must be guarded (no plaintext master key by default)
  46. execution finalizers must accept 'resuming', not only 'running'
  47. append-only audit tables must not gain CASCADE/SET NULL FKs
  48. template macro world must match talos.json capability_world
  49. integration crates must use talos_http_utils::trusted_client (no raw reqwest client builder)
  50. raw sqlx::query in talos-api/src/schema (must be 0)
  51. no talos-workflow-engine dependency in talos-*-repository crates
  52. silent try_get().unwrap_or reads (workspace-wide, must be 0)
  53. unguarded wasmtime Component::new in worker runtime (must route through the panic guard)  (clippy)
  54. lint self-consistency (check numbering + documented count)
  55. bare row.get() sqlx reads in DB-layer crates + controller bootstrap (must be 0)
  56. engine built with no gate-resolved actor (literal None or .without_actor())
  57. sub-engine built without actor-bind + ceiling narrowing (H2 escalation guard)
  58. registered Prometheus metric never incremented (dead metric)
  59. email-sender template Subject must route through encode_subject (RFC 2047)
  60. vector-similarity ORDER BY needs a unique tiebreaker
  61. signed JSON must be hashed as its exact wire bytes
  62. build.rs GIT_SHA stamping must be identical across crates
  63. one Rhai sandbox (discard print/debug + no raw rhai::Engine::new)  (clippy)
  64. every tests/*.rs binary is run by a CI runner
  65. dev Prometheus scrapes Talos and its rule files resolve
  66. compose bind mounts of tracked files must mount the DIRECTORY
  67. the fleet heartbeat must not reach the identity trust boundary
  68. catalog compiles must go through CatalogTemplate
  69. unconfigured tracing must mean disabled (no localhost default)
  70. writes keyed on a per-tenant-unique natural key must constrain the tenant column
  71. graph-node-id → UUID derivation must route through engine_node_uuid
  72. personal-information markers in the tracked tree (PUBLIC repo)
  73. env-var presence tests must treat empty as unset
  74. health-reporting handlers must not swallow reads into benign defaults
  75. whole-tree scans prune .claude worktrees and .git
  76. input-schema reads are classified, not defaulted
  77. __error reads are classified, not shape-assumed
  78. one production signing gate for NATS dispatch  (clippy)
  79. an integration read must not collapse a failure into "not found"
  80. one pinned Postgres image across compose, CI, tests and drills
  81. ARCHIVED is not ABSENT on a by-id execution read
  82. engine write-ceiling gates must notify the refusal recorder
  83. explicit updated_at = NOW() in an upsert on a trigger-maintained table
  84. signed-RPC actor mutations must sit behind the write-ceiling gate
  85. one SQL read-only/mutation classifier, with one home
  86. NOT EXISTS(workflow_executions) must know about sub-workflows
  87. a workflows liveness predicate must name the shared home
  88. every static sqlx statement must PREPARE against the real schema
  89. a configuration-reference Component cell must not claim a process that cannot read the variable
  90. a boolean env var must be parsed by the ONE shared vocabulary
  91. a vault key path in a log line must be rendered through the shared redactor
  92. an evidence path cited in an auditor-facing doc must exist and hold the code
  93. every container image this repository runs or builds from is digest-pinned
  94. admin_event_log has ONE writer
  95. every execution-row insert runs the actor budget check
  96. the CLAUDE.md engineering-log split lost nothing
  97. a documented env var with NO default must be TRANSPORTED

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
- **`make lint` enforces structural rules** via `scripts/lint-structural.sh`. 97 checks today (`bash scripts/lint-structural.sh --count` prints the live number, and check 54 fails the lint if this sentence's count goes stale), each tied to a specific past regression so it catches at PR-time the class of bug that survives `cargo check` cleanly but breaks at CI or request time. Each check's SPECIFICATION — rule, scope, opt-out marker, measured precision, stated limits — is the comment block above it in the script, which is authoritative. The one-line index is the digest subsection "Structural lint checks" above; the long entries this list carried until 2026-09-25 are archived verbatim in `docs/engineering-log/structural-lint-checks.md`. Checks 29, 53, 63 and 78 are enforced by CLIPPY (`clippy.toml` `disallowed-methods`, which resolves the call by type, so an alias or a UFCS call cannot hide one); their structural checks verify that config and where each sanctioned `// disallowed-method: <path> — <reason>` + `#[allow(clippy::disallowed_methods)]` sits. Adding a check: its comment block in the script, a line in the index.

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
- **Sigstore identity regexp pins to the workflow URL.** Format: `^https://github\\.com/OWNER/talos/\\.github/workflows/template-publish\\.yml@`. Without the trailing `@`, an attacker who creates a fork named `template-publish.yml-evil.yml` could match. The OIDC issuer pin (`https://token.actions.githubusercontent.com`) restricts to GitHub Actions tokens specifically. Cosign is bundled in the worker Dockerfile at a pinned version so verification doesn't depend on operator's PATH or apt repository state.

## HTTP middleware & router rules
- **`cors_middleware` short-circuits ALL `OPTIONS` requests** (`controller/src/main.rs::cors_middleware`). It builds an empty 200 response and returns immediately, never calling `next.run`. Consequence: an `OPTIONS` preflight cannot trigger ANY downstream middleware (including `csrf_protection_graphql`). Don't try to seed cookies or run validation logic via OPTIONS — pick a real GET endpoint.
- **`tower_cookies::CookieManagerLayer` on a sub-router merged AFTER the outer `CookieManagerLayer` is unreliable.** When a sub-router is `.merge`d into the parent app and you re-add `CookieManagerLayer + cookie-modifying middleware` inside that sub-router, `Set-Cookie` headers can fail to appear in the response (root cause not pinned down — likely a layer-ordering interaction with axum's response mapping). For cookie writes on routes that bypass the main cookie layer, build the `Set-Cookie` header by hand in the handler. See `seed_csrf_handler` for the reference pattern.
- **Probe and exempt routes need their own Extension layers.** `probe_routes` is merged AFTER the rate-limit layers (so kubelet probes can't be 429'd). The Extension layers (`db_pool`, `redis_client`, `nats_client`) attached to the main app DON'T propagate to merged sub-routers — re-attach them on the sub-router or the handlers panic with "Extension not found". The `mcp_router` follows the same pattern.
- **Per-IP rate-limit identification MUST use RFC 7239 right-to-left X-Forwarded-For walk** (`rate_limit::extract_client_ip`). Reading the leftmost entry is exploitable: any client behind a trusted proxy can prepend a fake IP and the server attributes their requests to it. The walk skips trusted-proxy entries from the right; the first untrusted entry is the real client.
- **Probe paths are exempt from rate limiting two ways**: (1) architectural — `probe_routes` merged after rate-limit layers; (2) defence in depth — `is_rate_limit_exempt_path()` early-returns from `rate_limit_middleware` and `global_rate_limit_middleware`. With Traefik on `externalTrafficPolicy: Cluster`, kube-proxy SNATs all external traffic to a single node IP, so without the exemption a busy site evicts kubelet probes from the per-IP bucket → pod marked NotReady → 502 cascade.
- **Helm controller probes use `/live` and `/ready`, not `/health`.** `/live` is a trivial process-alive check (no DB/Redis/NATS calls) — a Postgres hiccup can't restart the pod. `/ready` returns 503 only when Postgres is down (Redis/NATS report degraded but still 200). `/health` is the user-facing combined check, kept for the frontend's `seedCsrfCookie` and ad-hoc curl.
- **WebSocket handlers MUST extract Origin from the request HeaderMap** and pass it into `ws_auth::handle_websocket_auth` — passing `None` makes EVERY WS connection fail in production with "missing Origin header" because `is_production()` requires the header. The handshake still returns `101` (the upgrade succeeds), then the socket is immediately closed by `handle_websocket_auth`, which the browser surfaces as `WebSocket connection failed:` with no detail.
