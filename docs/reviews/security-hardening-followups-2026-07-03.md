# Security-hardening follow-ups — 2026-07-03

Companion to `docs/reviews/codebase-review-2026-07-03.md`. This tracks the
remediation of the review's findings and specifies the two deep protocol changes
that must be completed in a compile-capable, integration-testable environment.

## Status

| # | Finding | Status |
|---|---------|--------|
| 1 | Single fleet-wide `WORKER_SHARED_KEY` roots all signing → sandbox escape = cross-tenant forgery | **Reclassified** — per-worker HMAC does NOT fix this (see corrected analysis); genuine fix is an asymmetric-crypto RFC. HKDF primitive kept as a building block only |
| 2 | Process-local replay caches → replay across HA replicas | **Design specified below** |
| 3 | RLS shipped OFF by default | **Done** — `talos_db::enforce_production_rls_posture` fail-closes prod boot (opt-out `TALOS_ALLOW_RLS_DISABLED=1`) |
| 4 | Silent `try_get().unwrap_or()` masks schema drift | **Done** — structural-lint ratchet (check 52); highest-risk AEAD-format/id reads made fail-loud in `talos-execution-repository` + `talos-module-executions`; baseline lowered 526→524 |
| 5 | Aspiration-vs-reality doc gaps | **Done** — LLM-provider docs corrected (`llm_tier.rs`, `provider_tier`); sub-workflow-checkpoint and raw-socket `allowed_hosts` caveats documented in code; stale `update_protocol.py` deleted |

Items 3–5 are committed. Item 1 is **reclassified as an RFC-scale asymmetric
redesign** (a quick per-worker-key wire-up was found to be security theater under
symmetric HMAC — see the corrected Finding #1). Item 2 (distributed nonce) is a
genuine, tractable fix whose design is below; it changes the signed data-plane
verify path — the area `CLAUDE.md` flags as total-outage-prone (r300/r301) — so it
must land with `cargo check`/`cargo test` green AND an integration run against
live NATS + Redis. What is landed now is the safe,
additive foundation for #1.

---

## Finding #1 — Single fleet-wide worker key (CORRECTED: needs asymmetric crypto)

> **Correction (2026-07-03, verified against the code).** An earlier draft of
> this doc proposed per-worker HKDF *signing* keys as the fix and described a
> wiring plan. **That plan does not actually reduce the blast radius of a worker
> compromise under the current symmetric-HMAC architecture, and should not be
> shipped as a fix.** The analysis below supersedes it. The HKDF primitive that
> did land (`derive_worker_signing_key`) is kept only as a building block for the
> asymmetric redesign — it is not, on its own, a mitigation.

### Why HKDF-per-worker signing keys don't help here

The worker holds the fleet root (`WORKER_SHARED_KEY`, loaded as a
`WorkerKeyRing` in `worker/src/main.rs:1050`) because it needs it for three
things a compromise cannot avoid:

1. **Verify the controller's `JobRequest`** — symmetric HMAC (`verify_with_ring`,
   `worker/src/main.rs:543`). With HMAC, the ability to *verify* is the ability
   to *forge*: any key the worker can check controller messages with, it can also
   mint controller messages with.
2. **Decrypt the per-job secret envelope** — the AES key is HKDF-derived from the
   same root (`decrypt_with_ring`, `worker/src/main.rs:600`).
3. **Sign `JobResult` and all memory/graph/database/state RPC** — also the root
   (`worker/src/main.rs:359`; `talos-memory/src/rpc_auth.rs:5` states plainly it
   uses "the same `WORKER_SHARED_KEY`").

So a wasmtime sandbox escape recovers the root regardless of how `JobResult` is
signed. Once the attacker has the root they can derive **any** worker's HKDF
signing key at will, so per-worker signing keys add nothing. Deriving JobResult
signing per-worker while the worker still holds the root for (1) and (2) is
security theater: it changes the wire format without moving the trust boundary.

### The genuine fix (asymmetric — RFC-scale, out of scope for a wire-up)

The single-key blast radius can only be closed by removing root-equivalent
material from the worker, which requires asymmetric crypto:

- **Controller→worker (`JobRequest`):** replace HMAC with an Ed25519 signature.
  The controller holds the private key; workers hold only the controller's
  **public** key, so a compromised worker can verify JobRequests but cannot forge
  them. This alone closes the JobRequest-forgery half.
- **Worker→controller (`JobResult`, RPC):** each worker gets its own Ed25519
  keypair; the controller registers worker public keys. The worker signs with its
  private key; a compromise lets it sign only as itself. (This is where the landed
  HKDF primitive could instead become per-worker keypair *derivation* if a
  symmetric root-of-trust for provisioning is retained.)
- **Secret envelope:** the hard part. The worker must decrypt secrets without
  holding a fleet-wide decryption key. Options: seal each envelope to the
  dequeuing worker's X25519 public key (requires dispatching to a *known* worker,
  losing NATS queue-group load-balancing), or a per-execution ephemeral-key
  scheme. Needs a design spike; this is the piece that makes it RFC-scale rather
  than a patch.

**Recommended next step:** open an RFC (`docs/rfcs/`) for an asymmetric
worker-trust boundary covering the three directions above, the key-distribution /
registration model, wire-format versioning, and a staged rollout. Until then,
finding #1 is best treated as a **known, documented residual risk** whose actual
mitigations today are the WASM sandbox itself (fuel/epoch/memory limits, proposal
lockdown, per-tier linkers) keeping native-code escape hard, plus the tier-1
data-egress gate — not the per-worker HMAC scheme.

### What remains landed

`talos_workflow_job_protocol::derive_worker_signing_key(root, worker_id)` +
its six unit tests stay in the tree as a **building block** (a domain-separated
per-identity KDF) for the eventual asymmetric scheme. Its doc comment already
states it is a primitive, not a wired fix. No sign/verify path calls it, so it is
inert and harmless.

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
