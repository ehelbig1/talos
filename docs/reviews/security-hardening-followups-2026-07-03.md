# Security-hardening follow-ups — 2026-07-03

Companion to `docs/reviews/codebase-review-2026-07-03.md`. This tracks the
remediation of the review's findings and specifies the two deep protocol changes
that must be completed in a compile-capable, integration-testable environment.

## Status

| # | Finding | Status |
|---|---------|--------|
| 1 | Single fleet-wide `WORKER_SHARED_KEY` roots all signing → sandbox escape = cross-tenant forgery | **Primitive landed**, wiring specified below |
| 2 | Process-local replay caches → replay across HA replicas | **Design specified below** |
| 3 | RLS shipped OFF by default | **Done** — `talos_db::enforce_production_rls_posture` fail-closes prod boot (opt-out `TALOS_ALLOW_RLS_DISABLED=1`) |
| 4 | Silent `try_get().unwrap_or()` masks schema drift | **Done** — structural-lint ratchet (check 52), baseline 526, may only go down |
| 5 | Aspiration-vs-reality doc gaps | **Done** — LLM-provider docs corrected (`llm_tier.rs`, `provider_tier`); sub-workflow-checkpoint and raw-socket `allowed_hosts` caveats documented in code; stale `update_protocol.py` deleted |

Items 3–5 are committed. Items 1–2 change the signed data plane — the area
`CLAUDE.md` flags as total-outage-prone (r300/r301) — so they must land with
`cargo check`/`cargo test` green AND an integration run against live NATS
(+ Redis for #2), which the review sandbox could not provide (crates.io is
proxy-blocked there, so nothing compiles). What is landed now is the safe,
additive foundation for #1.

---

## Finding #1 — Per-worker derived signing keys

### What's landed (additive, zero behavior change)

`talos_workflow_job_protocol::derive_worker_signing_key(root, worker_id)` —
`HKDF-SHA256(ikm = root, salt = "talos/worker-shared-key/per-worker-signing/v1",
info = worker_id)`, domain-separated from every envelope-AEAD subkey. Six unit
tests pin determinism, per-`worker_id` distinctness, per-root distinctness,
envelope-key domain separation, label stability, and empty-id definedness. No
existing sign/verify path calls it yet.

### The threat it closes

Today a worker signs with the raw root, and `JobResult.worker_id` is
self-reported (`worker/src/worker_identity.rs:31` — *"any process holding
`WORKER_SHARED_KEY` can sign as any `worker_id`"*). A wasmtime sandbox escape
extracts the root from worker memory → the attacker forges signed RPC for any
`actor_id`/tenant and decrypts any job envelope. The fix makes each worker hold
**only its own derived key**, never the root.

### Wiring plan (must be compiled + integration-tested)

1. **Signature-scheme discriminant.** Add a `sig_scheme: u8` field (`#[serde(default)]`
   → 0) to `JobResult` and `PipelineJobResult`, appended at the END of each
   `signing_payload()` per the wire-format-stability rule. `0` = root-direct
   (legacy), `1` = per-worker-derived. Bind it into the HMAC so it can't be
   downgraded on the wire.
2. **Worker sign path.** `sign_with_worker_id` selects the key:
   - If a derived key was provisioned (see step 4), sign with it and set
     `sig_scheme = 1`.
   - Else derive from the root in-process (transitional) and set `sig_scheme = 1`.
   - The bare `sign()` back-compat wrapper stays `sig_scheme = 0` for test fixtures.
3. **Controller verify path.** In `verify_*_core`, branch on `sig_scheme`:
   - `1` → `key = derive_worker_signing_key(root_or_ring_member, self.worker_id)`,
     then the existing HMAC+freshness+replay logic against that derived key.
     Reject empty `worker_id` under scheme 1 (an empty id is not a real worker).
   - `0` → today's root-direct verification, but gate acceptance behind
     `TALOS_ACCEPT_LEGACY_ROOT_SIG` (default ON during rollout). The key-ring
     variants (`verify_with_ring`) derive per ring member so rotation composes.
4. **Provisioning (the part that actually reduces blast radius).** A worker must
   run with its derived key and NOT the root. Options, cheapest first:
   - Env `TALOS_WORKER_DERIVED_KEY` (hex) injected per-pod by an init container
     that calls a controller endpoint `POST /internal/worker-key` (mTLS-authed,
     in-cluster only, NetworkPolicy-restricted) returning
     `derive_worker_signing_key(root, pod_name)`. The controller holds the root;
     the worker Deployment stops mounting `WORKER_SHARED_KEY`.
   - Until provisioning is deployed, the worker derives from the root in-process
     (step 2 fallback): the wire format and verify path are already correct, so
     provisioning becomes a pure ops change with no code churn.
5. **Enforcement flip.** Once all workers run scheme 1 with provisioned keys, set
   `TALOS_ACCEPT_LEGACY_ROOT_SIG=0` so root-direct signatures are refused —
   closing the forge path. Mirror the env-KEK/RLS guard style: loud SIEM log when
   a legacy signature is accepted during the window.
6. **RPC layer parity.** Apply the same scheme to `talos_memory::rpc_auth` (the
   memory/graph/database/state RPCs share the root). Same discriminant approach;
   `actor_id` is already host-supplied (not guest-controllable), so the RPC side
   binds the derived key to the signing worker identically.

### Test matrix

Unit: sign-scheme-1 → verify-scheme-1 round-trip; scheme-1 signature from
worker-A rejected when re-labeled worker-B; scheme-0 rejected when
`TALOS_ACCEPT_LEGACY_ROOT_SIG=0`; ring rotation across derived keys; empty
worker_id rejected under scheme 1. Integration: a real worker pod signing a
`JobResult` over NATS and the controller verifying it end-to-end, plus the
crash-recovery resume path (which re-stamps tier) still verifying.

---

## Finding #2 — Distributed replay-nonce store

### The gap

`NONCE_CACHE` (`talos-memory/src/rpc_auth.rs`) and `JOB_NONCE_CACHE`
(`talos-workflow-job-protocol/src/lib.rs`) are per-process statics. Under the
horizontally-scaled controller the platform targets, a captured signed message
replayed to a *different* replica within the 60 s freshness window is admitted —
single-use degrades to "freshness-window-bounded replay across the fleet." HMAC
+ freshness still hold; only the single-use guarantee weakens.

### Design (must be compiled + integration-tested)

1. **`ReplayGuard` trait**, injected, defaulting to today's behavior:
   ```rust
   pub trait ReplayGuard: Send + Sync {
       /// Ok(true) = first sighting (recorded); Ok(false) = replay.
       /// Err = backend unavailable → caller applies the fail policy.
       fn check_and_record(&self, key: &str, ttl_secs: u64) -> Result<bool, ReplayError>;
   }
   ```
   The current `Mutex<HashMap>` / two-generation `DashMap` become the
   `ProcessLocalGuard` impl — the default, so behavior is byte-identical until an
   operator opts in.
2. **`RedisReplayGuard`.** `SET talos:nonce:{subject}:{nonce} 1 NX PX {ttl_ms}`
   where `ttl_ms ≥ (max_age_secs + future_skew) * 1000`. Reply `nil` (key
   existed) = replay. Redis is already a required service and already TLS-gated
   in prod (`tls-prod-gate-redis`), so no new dependency.
3. **Fail policy on Redis outage.** Fail *closed* for signed control-plane
   messages if `TALOS_REPLAY_FAIL_CLOSED=1`; otherwise fall back to the
   process-local guard with a rate-limited WARN and a `target: "talos_security"`
   event. Default to fallback (availability) but document the closed option for
   high-assurance deploys. HMAC + freshness always still apply, so fallback is
   degraded-not-open.
4. **Keying.** Namespace by subject/message-type so a memory nonce and a job
   nonce can't collide, matching the existing per-type `NONCE_LABEL`.
5. **Wire-in.** `verify_core` / `record_nonce_or_replay_err` call the injected
   guard instead of the module static. The guard is constructed once at boot
   (controller wiring) and threaded through the verifier; the crate keeps a
   process-local default so its own tests need no Redis.

### Test matrix

Unit: `ProcessLocalGuard` parity with today (existing tests unchanged);
`RedisReplayGuard` NX semantics against a mock. Integration: replay the same
signed message to two controller replicas sharing one Redis → second is rejected;
Redis-down → fallback path admits once per replica with the WARN emitted;
`TALOS_REPLAY_FAIL_CLOSED=1` → Redis-down rejects.

---

## Why these two are handoffs, not blind commits

`CLAUDE.md`'s verify-once rule and the r300/r301 incident note that a mistake in
this exact code path fails *every* job deterministically. Both changes are
therefore gated on: `cargo check --workspace` + `cargo test -p
talos-workflow-job-protocol -p talos-memory` green, `make lint` green, and a
live-NATS (+ Redis for #2) integration run. The additive primitive for #1 is
landed now because it is verifiable in isolation and fixes the derivation
contract; the behavior-changing wiring waits for that environment.
