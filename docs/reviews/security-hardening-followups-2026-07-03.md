# Security-hardening follow-ups — 2026-07-03

Companion to `docs/reviews/codebase-review-2026-07-03.md`. This tracks the
remediation of the review's findings and specifies the two deep protocol changes
that must be completed in a compile-capable, integration-testable environment.

## Status

| # | Finding | Status |
|---|---------|--------|
| 1 | Single fleet-wide `WORKER_SHARED_KEY` roots all signing → sandbox escape = cross-tenant forgery | **Substantially addressed** (RFC 0010 P1+P2 landed) — Ed25519 asymmetric signing on BOTH directions: controller→worker dispatch (P1) and worker→controller results + all 5 signed RPC protocols (P2), each keyed to a per-worker identity. A compromised worker can now forge only *as itself*, never as another worker or the controller. Opt-in, default byte-identical HMAC; operator keygen + rollout runbook shipped. Remaining: P3 envelope sealing (last root-key removal, blocked on the D3a/D3b design fork) + P4 enforcement flip |
| 2 | Process-local replay caches → replay across HA replicas | **Design specified below** |
| 3 | RLS shipped OFF by default | **Done** — `talos_db::enforce_production_rls_posture` fail-closes prod boot (opt-out `TALOS_ALLOW_RLS_DISABLED=1`) |
| 4 | Silent `try_get().unwrap_or()` masks schema drift | **Done** — structural-lint ratchet (check 52); highest-risk AEAD-format/id reads made fail-loud in `talos-execution-repository` + `talos-module-executions`; baseline lowered 526→524 |
| 5 | Aspiration-vs-reality doc gaps | **Done** — LLM-provider docs corrected (`llm_tier.rs`, `provider_tier`); sub-workflow-checkpoint and raw-socket `allowed_hosts` caveats documented in code; stale `update_protocol.py` deleted |

Items 3–5 are committed. Item 1 was **reclassified as an RFC-scale asymmetric
redesign** (a quick per-worker-key wire-up was found to be security theater under
symmetric HMAC — see the corrected Finding #1) and is now **substantially
addressed**: RFC 0010 phases P1 (Ed25519 dispatch) and P2 (per-worker Ed25519 on
results + all five signed RPC protocols) are landed, gated, and pushed, each an
opt-in, default-byte-identical-HMAC change. The last root-equivalent key removal
(P3 envelope sealing) is blocked on the D3a-vs-D3b design fork the RFC flags, and
the P4 enforcement flip follows once every worker signs Ed25519 — both tracked in
RFC 0010. Item 2 (distributed nonce) is done (`talos-replay-guard`). The signed
data-plane verify path — the area `CLAUDE.md` flags as total-outage-prone
(r300/r301) — carries the full dual-verify (HMAC + Ed25519) behind a
config-composition test (`operator_keygen_config_composes_both_directions`) that
drives the keygen output through both loaders and both verify directions.

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

**Next step — written:** [RFC 0010 — Asymmetric worker-trust
boundary](../rfcs/0010-asymmetric-worker-trust-boundary.md) now specifies the
genuine fix: Ed25519 for controller→worker dispatch, per-worker Ed25519 keypairs
for worker→controller, envelope sealing (X25519/ECIES or per-execution), a
`crypto_scheme`-versioned staged rollout, and the open questions that block P3.
Until it ships, finding #1 is a **known, documented residual risk** whose actual
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

## Finding #2 — Distributed replay-nonce store — **LANDED (opt-in)**

### The gap

`NONCE_CACHE` (`talos-memory/src/rpc_auth.rs`) and `JOB_NONCE_CACHE`
(`talos-workflow-job-protocol/src/lib.rs`) are per-process statics. Under the
horizontally-scaled controller the platform targets, a captured signed message
replayed to a *different* replica within the 60 s freshness window is admitted —
single-use degrades to "freshness-window-bounded replay across the fleet." HMAC
+ freshness still hold; only the single-use guarantee weakens.

### What landed

New crate **`talos-replay-guard`** — an additive layer, *not* a rewrite of the
sync verify core:

- **`ReplayGuard` (async) trait** + `ReplayOutcome { Fresh, Replay, Unavailable }`.
- **`ProcessLocalReplayGuard`** — `Mutex<HashMap>` with TTL sweep + hard cap
  (mirrors the existing `JobNonceCache`); the trait's reference impl.
- **`RedisReplayGuard`** — `SET talos:nonce:{key} 1 NX PX {ttl_ms}` over a
  multiplexed `ConnectionManager`; `Some("OK")` → `Fresh`, `nil` → `Replay`,
  error → `Unavailable`. Redis is already a required, prod-TLS-gated dependency.
- **Global registration** (`register_shared_replay_guard` / `shared_replay_guard`)
  mirroring `rpc_auth::register_hmac_key_ring`, and a **fail policy** helper
  (`admit` + `fail_closed_from_env`; default fail-**open** so a Redis blip
  degrades to today's per-replica protection, never opening a forgery hole).

**Wiring** (`talos-rpc-subscribers/src/lib.rs`): all five signed-RPC subscribers
(`graph.search`, `memory.op`, `database.query`, `state.write`,
`integration_state.op`) now do
`if !req.verify() || !crossreplica_replay_ok(subject, req.actor_id, &req.nonce).await`.
The async cross-replica check runs **only after** the sync per-replica
`verify()` (HMAC + freshness + process-local nonce) passes — so forged/locally-
replayed messages never touch Redis — and namespaces the key on
`subject:actor_id:nonce`.

**Boot registration** (`controller/src/main.rs::register_distributed_replay_guard`):
opt-in via `TALOS_DISTRIBUTED_REPLAY`, requires `REDIS_URL`, registered before
the subscribers spawn. **Default OFF → no guard registered → `shared_replay_guard()`
returns `None` → subscriber behaviour is byte-identical to before.**

### Verified

`cargo test -p talos-replay-guard` passes, including a **live-Redis integration
test** (`redis_fresh_then_replay_when_available`, gated on `TALOS_TEST_REDIS_URL`)
that proves Fresh→Replay single-use against a real `redis-server`. Process-local
parity, the `admit` fail-policy matrix, and single-shot registration are unit-
tested. `talos-rpc-subscribers` and `controller` compile clean with the wiring.

### Remaining (follow-up)

- **`JobResult` / `PipelineJobResult` primary-verify sites** (the engine
  dispatcher reply-inbox handler) should get the same `crossreplica_replay_ok`
  layer with a 300 s TTL (matching `verify`'s `max_age`). The `talos.results.*`
  observer subscriber (`main.rs`) is `Verifier::Observer` and idempotent, so it
  deliberately stays unguarded. Same pattern as the RPC sites.
- **Multi-replica integration test**: two controllers sharing one Redis, replay
  the same signed RPC to the second → rejected. Needs a two-node harness (out of
  scope for a single-process test); the live-Redis unit test already proves the
  store's NX single-use semantics that this relies on.
- Consider `TALOS_DISTRIBUTED_REPLAY` defaulting ON in the HA Helm values once
  the multi-replica test is in CI.

---

## Notes on handoffs vs. landed changes

`CLAUDE.md`'s verify-once rule and the r300/r301 incident note that a mistake in
this exact code path fails *every* job deterministically. Both changes are
therefore gated on: `cargo check --workspace` + `cargo test -p
talos-workflow-job-protocol -p talos-memory` green, `make lint` green, and a
live-NATS (+ Redis for #2) integration run. The additive primitive for #1 is
landed now because it is verifiable in isolation and fixes the derivation
contract; the behavior-changing wiring waits for that environment.
