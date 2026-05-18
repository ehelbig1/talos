# Platform primitive review checklist

Walk this before committing any new signed-NATS-RPC primitive
(integration_state, memory_rpc, graph_rpc, database_rpc, state_rpc —
future additions follow the same shape). It captures every issue found
during the integration_state review pass in 2026-04-15 so the next
primitive doesn't repeat them.

**Related**: `docs/integration-pattern.md` is one layer up — for
building a user-facing integration (watch channels, webhooks, WASM
dispatch) ON TOP of an existing primitive. Use this doc when
adding a `talos.<verb>.<op>` RPC subject; use the integration
pattern doc when wiring a new push-notification provider on top of
`integration_state`.

Rule of thumb: if you answer "I didn't check that" to any item, check it
before shipping. Ten individual fixes landed on integration_state across
six review passes (see `git log --oneline` for commits `507e617..3e13759`)
even though the initial implementation was pattern-copied from
`memory_rpc`; an upfront checklist would have caught most in the first
pass.

## 1. Schema + migration

- [ ] Migration is idempotent (`CREATE TABLE IF NOT EXISTS`, `ALTER TABLE ADD COLUMN IF NOT EXISTS`, `DROP TRIGGER IF EXISTS`).
- [ ] Every CHECK constraint mirrors the Rust-side validator (charset, length caps, regex). Operators should not be able to produce a DB-valid row that the RPC validator rejects, or vice versa. The DB is the last line of defense.
- [ ] Partial indexes on nullable or filter-only columns (`WHERE col IS NOT NULL`) so rows without the column pay zero index cost.
- [ ] Unique-constraint backing index covers the primary lookup pattern.
- [ ] If adding a new column used by dispatch: every SELECT query in the controller that constructs the struct must be updated. A `.unwrap_or(None)` fallback on `try_get` masks the issue — the code compiles fine but the field is NULL for every row. Grep `try_get.*unwrap_or(None)` for landmines.

## 2. RPC protocol + signing

- [ ] Variant tags for the op enum are fixed `u8` constants with a compile-time `_TAG_UNIQUENESS_GUARD: [u8; N] = {...}` assertion so new variants must claim a fresh byte.
- [ ] `sign_body_bytes` has a comment declaring the field order is load-bearing and new fields must APPEND to the end. Reordering invalidates every deployed signature.
- [ ] Every identity-bearing field is inside the signed body: integration/tenant/user/actor/subject/nonce/timestamp. Missing any one = on-wire tampering redirects operations to a different scope without invalidating the signature (see `JobRequest.integration_name` gap).
- [ ] Signature binding extends to both `new_signed` / `verify`. If you can swap a field post-sign and still pass verify, the field isn't bound.
- [ ] JSON values in the sign body flow through `rpc_auth::canonical_json_bytes` (sorted keys, depth-bounded) so serde_json feature flags in the dep tree can't invalidate signatures.
- [ ] Numeric fields signed as LE bytes, not decimal text — eliminates leading-zero / sign-prefix ambiguity.
- [ ] Non-finite `f64` inputs rejected at sign time (IEEE 754 NaN has multiple bit patterns).
- [ ] Nonce generated via `rpc_auth::random_nonce()`; `SUBJECT_NAME` const is distinct from every other RPC so nonce-cache entries don't collide across subjects.
- [ ] Unit tests assert cross-{integration, user, actor, subject} signature swaps FAIL verify. Three-line tests, huge assurance return.

## 3. Subscriber

- [ ] Verify signature BEFORE any DB work.
- [ ] Call `rpc_auth::check_and_record_nonce` after verify — both must succeed.
- [ ] Internal errors never return raw DB/provider text to the client. `tracing::error!` the real error, return generic `Internal("database operation failed")`. Raw Postgres error strings leak schema (constraint names, column references).
- [ ] Row-count caps enforced server-side (client-side only isn't enforced for un-signed / mis-signed requests). Accept TOCTOU on soft caps if concurrent writes are low-volume; document the tradeoff.
- [ ] Every dynamic-SQL filter value is `.bind()`'d — never string-interpolated — even when the value is guaranteed safe. No injection surface, no "careful now" debate at review time.
- [ ] LIKE pattern inputs escape `\`, `%`, `_` so user-supplied prefixes don't silently become wildcards.
- [ ] Read queries filter expired rows (`AND (expires_at IS NULL OR expires_at > now())`) — reads don't leak rows that haven't been swept yet.
- [ ] Background sweep task uses `DELETE ... WHERE id IN (SELECT ... LIMIT N)` to bound per-tick DELETEs. An unbounded DELETE on a backlog can hold row-locks long enough to stall writers.
- [ ] Subscriber tasks spawned via `in_flight.spawn` (tracked), NOT `tokio::spawn` (orphaned at shutdown). Graceful drain loop requires tracked tasks.
- [ ] Per-op timeout wraps the DB future so a stalled Postgres doesn't zombie-hold semaphore permits indefinitely (gap in the existing RPC family — worth fixing in new primitives).
- [ ] Metrics: `record_rpc_metric` with split `queue_ms` / `exec_ms` and a distinct outcome tag for every failure mode (`unauthorized`, `replay`, `invalid`, `timeout`, `storage_full`, `not_found`, `internal`).

## 4. Worker host impl

- [ ] Authorization pre-check returns a specific error (`Unauthorized`, `NotAvailable`) BEFORE any NATS round-trip. A module that lacks the prereq should fail in microseconds, not after paying a 3s timeout.
- [ ] `self.is_cancelled()` checked at the top of every host fn. A cancelled execution must not be able to extend its blast radius by kicking off new RPCs.
- [ ] Owned-prereqs pattern (`fn ctx_owned(&self) -> Result<(Owned...), Error>`) so no `&mut self` borrow crosses an await boundary. WASI handles in `TalosContext` aren't `Send`; holding `&mut self` across `.await` fails bindgen's Send bounds.
- [ ] No WIT parameter exists that the guest can use to spoof an identity value (integration_name, actor_id, user_id). These come from `TalosContext` only — the worker populates from the signed `JobRequest`, which the engine populates from DB metadata.
- [ ] `self.metrics.record_host_function_call(..)` at the end so both success and failure are measured.
- [ ] Error mapping is exhaustive (`match` on every variant, no `_ =>` catch-all) so a new RPC error variant fails to compile until a mapping is chosen.

## 5. Wire-format stability

- [ ] Field order in `sign_body_bytes` is APPEND-ONLY after the first deploy.
- [ ] Field order in `JobRequest::signing_payload` / `PipelineJobRequest::signing_payload` is APPEND-ONLY for any new identity field. A rolling deploy across versions with different signing payloads fails verify on cross-version messages.
- [ ] New `ListFilter` fields appended to the struct definition AND to the sign body in the same order.
- [ ] `MAX_CANONICAL_DEPTH = 128` (matches serde_json default) enforced on any JSON that enters the sign body.

## 6. Defense in depth — size + range caps

- [ ] Top-level value cap (64 KiB matches `actor_memory`) enforced at client sign time AND at subscriber. Defense in depth protects against a rogue client that bypasses signing somehow.
- [ ] Per-indexed-column cap on string slots (~512 bytes) — oversize strings bloat the btree index and are a DoS vector for shared disk. The value cap doesn't cover slot columns.
- [ ] Numeric range caps on timestamp slots explicit (`MIN_TS_MS`..`MAX_TS_MS` for `chrono::DateTime<Utc>` safe range). Out-of-range values silently converted to NULL by `timestamp_millis_opt().single()` create a "caller thinks they set an index but it's NULL" confusion.
- [ ] TTL seconds capped (10 years) so an int-overflow or bad-math caller can't poison a row with a ridiculous expiry.
- [ ] Filter-side input cap (prefix length, idx_eq length) so a rogue client can't force full-index scans with huge bounds.

## 7. Dispatch-path plumbing

- [ ] Every `SELECT ... FROM wasm_modules` that constructs a `WasmModule` struct includes the new column. The `.unwrap_or(None)` fallback on the struct side is defensive only — the column must appear in SELECT for real values to flow.
- [ ] `ModuleRegistry::get_module` (canonical getter) selects the column.
- [ ] Dispatch-hot-path `Fallback 0` (by-name) and `Fallback 1` (by template_id) queries select the column.
- [ ] `ModuleExecutionInfo` propagates the column.
- [ ] `JobRequest` / `PipelineStep` carry the column.
- [ ] `TalosContext` field populated by `SecurityPolicy` thread.
- [ ] Both `execute_job_with_full_features` AND the pipeline-step code path populate the field.

## 8. Testing

- [ ] Sign-time validator unit tests cover every rejection reason (oversized value, oversized slot, out-of-range ts, empty key, bad integration_name).
- [ ] Signature-binding unit tests swap each identity field post-sign and assert verify fails. One test per field that the PER-RPC `sign_body_bytes` binds (e.g. integration_name, user_id, op, timestamp). Cross-{actor, subject, nonce} binding is enforced at the `rpc_auth` layer and already covered by its own tests — you don't need to re-test those at the per-RPC level, but you MUST verify your per-RPC body actually includes the fields you care about.
- [ ] Tamper tests for JobRequest-level / PipelineStep-level identity fields specifically.
- [ ] Wire-format stability test: build a canonical request in two different ways (e.g. different JSON key insertion orders) and assert bytes match after canonicalization.
- [ ] Integration test against live Postgres (gated on `TALOS_TEST_DATABASE_URL`) covering the full set/get/delete/list round-trip, cross-(integration, user) isolation, TTL expiry → sweep, and the row-count cap. This is the one category the existing platform primitives consistently defer — it's worth not deferring on the next one.

## 9. Documentation + ops

- [ ] Wire-format stability rule block inside `sign_body_bytes` (append-only discipline).
- [ ] CLAUDE.md RPC section updated with the new subject name, concurrency cap, and security invariants.
- [ ] New MCP tool for operator inspection of the table (read-only, auditable — no bulk mutation).
- [ ] Sweep task logs batch size so operators can see when the per-tick cap is being hit (backlog building up).

## 10. End-to-end plumbing check

When you think the primitive is done, verify by running a real module that uses it. This catches the "everything is wired, but nothing can USE it because compile_custom_sandbox doesn't accept the arg" class of gap that bit integration_state.

- [ ] `compile_custom_sandbox` MCP handler accepts any new compile-time declaration.
- [ ] `install_module_from_catalog` accepts it.
- [ ] `WorkflowRepository::insert_node_template` / `update_node_template_wasm` / `upsert_wasm_module_for_template` thread it.
- [ ] End-to-end: compile a toy module that uses the new WIT interface, call it from a workflow, verify the DB row exists. Do this BEFORE declaring the primitive done.

## Meta — how to run the review itself

Single upfront review rarely catches everything. Run N focused passes over the code, each with a different lens:

1. **Schema + migration correctness** — read every CREATE/ALTER line.
2. **RPC wire format** — trace the sign body byte-by-byte.
3. **Subscriber SQL** — read every query, every bind, every error-return.
4. **Worker host impl** — trace every host function, check is_cancelled + prereqs + owned-pattern.
5. **Cross-layer identity propagation** — follow a value from DB → engine → JobRequest → worker context → host fn → RPC body. Every hop a possible drop.
6. **Defense-in-depth + HMAC commitment** — does every identity field appear in the signing payload?
7. **End-to-end** — actually run it.

Expect to find something real in each of the first 5-6 passes. The integration_state review found 9 issues across 6 passes; pattern-copying from an existing primitive didn't substitute for the checklist.
