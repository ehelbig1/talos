# Functional & governance audit — 2026-06-25

A live, end-to-end audit of a running Talos stack (`make up`), driven through the
real API surfaces (GraphQL, webhooks, scheduler, WS) rather than unit tests. The
goal was to exercise the data-plane and governance paths a real operator hits and
find correctness bugs that pass `cargo check` and the unit suite but break at
request time.

**Outcome: 8 real bugs found and fixed (all live-verified, all merged), two
systemic bug *classes* identified and swept to exhaustion, and ~16 surfaces
verified clean.** This doc captures the bugs, the two classes (so they can be
frozen with structural lints), and the negative results (so they aren't
re-investigated).

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

Five bugs, each a different way to violate it:

| PR | Path | Violation |
|----|------|-----------|
| #261 | GraphQL `trigger_workflow` | created `queued`, never promoted to `running`; the `running`-guarded `mark_execution_completed` then no-op'd → stuck `queued` |
| #263 | engine pipeline dispatch | wrote a **node id** into `module_executions.module_id` (FK violation) → per-step tracking dropped |
| #267 | webhook-fired module | INSERTed `module_executions` `running`, **never finalized** (inline request/reply, no result subscriber) |
| #268 | workflow-chain dispatch | the `'running'` INSERT ran in a fire-and-forget `tokio::spawn`, **racing** the inline fast-fail finalizer; finalizer won the race → orphaned `running` |
| (n/a) | scheduler, actor-handoff, retry, replay | **audited — clean**: all *await* the create/transition-to-`running` before spawning the run, and finalize both arms |

**Why the unit suite missed all five:** the MCP / `ExecutionOrchestrationService`
path creates rows as `running` (not `queued`) and finalizes synchronously, so
MCP-driven tests pass. The bugs lived only on the GraphQL/webhook/chain dispatch
paths.

**Recommended structural lint:** for each `INSERT INTO {workflow,module}_executions`
that sets a non-terminal status, require a matching terminal-status writer
reachable in the same module/path; flag any INSERT inside a `tokio::spawn` whose
finalizer is outside that spawn (the #268 race shape). At minimum, a `// allow-…`
-gated grep that pairs each such INSERT with a `mark_execution_{completed,failed}`
/ `complete_execution_from_worker` / upsert finalizer.

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

**Recommended structural lint:** fail if any table with the
`prevent_audit_modification` trigger has an incoming FK with `confdeltype IN ('c','n')`.
A migration-time check (the four audit tables are a closed set today).

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

Plus **#262** — restored four onboarding fixes (`/auth/csrf` dev proxy, catalog
seeding default, self-loop edge guard, frontend port docs) dropped by #259's
squash merge.

---

## Open follow-ups (noted, not yet fixed)

- **Module-approval status semantics.** The module-level `requires_approval_for`
  path marks the execution `failed` (with an "Execution paused…" message) and
  relies on *fail → approve → retry*, whereas the confidence-gate path *suspends*
  to `waiting` and resumes. After #269 the approve step works, but the two
  approval mechanisms should be reconciled — `failed` is a misleading status for
  "pending approval", and a `failed` row is what dashboards/alerts surface.
- **Webhook FK-routing log noise.** The WASM-log handler routes
  `workflow_execution_logs` vs `module_execution_logs` by attempting the workflow
  insert and catching the FK violation. Functionally correct + documented as
  intentional, but it emits a Postgres `ERROR` line per standalone-module log —
  noisy for log-based alerting. Optional: a cheap `EXISTS` pre-check, or tag the
  log's execution kind on the wire.
- **Budget USD cap is inert.** `check_execution_allowed` enforces actor status +
  per-hour rate at trigger time, but the lifetime-USD cap depends on consumption
  tracking that is documented as *"Always 0 until budget tracking is wired."*
  Expected/incomplete, not a bug — but the schema exposes `total_budget_usd` as if
  enforced.

---

## Verified clean (negative results — don't re-investigate)

- **Class A remainder:** scheduler, actor-handoff, retry, replay all finalize
  correctly (await create-to-`running` before spawning the run).
- **Class B remainder:** `audit_events` has no cascade/set-null FK.
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
