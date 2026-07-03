# RFC 0010 — Asymmetric worker-trust boundary

**Status:** In progress (P1 landing)
**Author:** Codebase review follow-up
**Date:** 2026-07-03

> **P1 status (landed, opt-in).** The Ed25519 dispatch scheme is implemented and
> unit-tested end-to-end at the protocol layer, and wired into the primary
> dispatch path: `crypto_scheme` discriminant + `sign_ed25519` / `verify_ed25519`
> / `verify_dispatch` on `JobRequest`/`PipelineJobRequest`
> (`talos-workflow-job-protocol`, 11 tests); `DispatchSigner` on the engine
> `NatsNodeDispatcher`; controller selects it via `TALOS_DISPATCH_SCHEME=ed25519`
> + `TALOS_CONTROLLER_SIGNING_KEY` (`talos-engine::nats_run`); the worker
> dual-verifies via `TALOS_CONTROLLER_PUBLIC_KEY[_PREVIOUS]` and enforces
> Ed25519-only under `TALOS_DISPATCH_REQUIRE_ED25519` (the P4 flip). **Default
> off → HMAC unchanged.** Remaining P1 wiring (follow-up): the module-push sign
> sites (`talos-webhooks`, `talos-gmail`, `talos-google-calendar`) and the
> dispatcher retry re-sign paths still sign HMAC — safe during dual-verify, but
> all must move to `DispatchSigner` before the P4 enforcement flip.
**Related:** `docs/reviews/codebase-review-2026-07-03.md` (finding #1),
`docs/reviews/security-hardening-followups-2026-07-03.md` (corrected Finding #1)

## TL;DR

Today one fleet-wide symmetric key (`WORKER_SHARED_KEY`) roots *everything* on
the worker↔controller boundary: it verifies the controller's `JobRequest`, signs
the worker's `JobResult` and every memory/graph/database/state RPC, and (via
HKDF) derives the per-job secret-envelope AES key. Because the worker runs
untrusted WASM, a single sandbox escape recovers this key and yields **total
cross-tenant forgery + decryption** of the entire data plane.

This RFC replaces the symmetric boundary with **asymmetric crypto** so the
worker holds no key that can forge controller messages or decrypt other jobs'
secrets:

- **Controller→worker** (`JobRequest`, `PipelineJobRequest`): Ed25519. The
  worker holds only the controller's **public** key — it can *verify* but not
  *mint* dispatches.
- **Worker→controller** (`JobResult`, RPC): per-worker Ed25519 keypairs. The
  controller registers worker public keys; a compromised worker can sign only as
  itself.
- **Secret envelope**: seal per-job secrets so only the executing worker can
  open them, without a fleet-wide decryption key resident in the worker.

**What it buys:** a WASM sandbox escape is bounded to the secrets of the jobs
currently in-flight *on that worker*, and cannot forge dispatches or RPC for any
other actor/tenant. **What it costs:** a wire-format break, a key-distribution /
registration mechanism, and (for the envelope) a design trade-off against NATS
queue-group load-balancing. This is a multi-phase, several-week change.

## Context

### Why the current shape doesn't work

The review's finding #1 originally proposed *per-worker HKDF signing keys* as
the fix. Investigation of the code proved that is **security theater under
symmetric HMAC** (see the corrected follow-up doc). The worker must hold the
root `WORKER_SHARED_KEY` regardless, because:

1. It **verifies** `JobRequest` with symmetric HMAC (`worker/src/main.rs:543`,
   `req.verify_with_ring`). With HMAC, the capability to *verify* is the
   capability to *forge* — any key that checks controller messages can also mint
   them.
2. It **decrypts** the per-job secret envelope with a key HKDF-derived from the
   same root (`worker/src/main.rs:600`, `decrypt_with_ring`).
3. It **signs** `JobResult` and all RPC with the root (`worker/src/main.rs:359`;
   `talos-memory/src/rpc_auth.rs:5` — "the same `WORKER_SHARED_KEY`").

A sandbox escape recovers the root from worker memory, and with it can derive any
per-worker HKDF key. The only way to move the trust boundary is to remove
root-equivalent material from the worker, which requires asymmetric primitives.

### Trust model after this RFC

| Direction | Primitive | Worker holds | A compromised worker can… |
|---|---|---|---|
| Controller→worker dispatch | Ed25519 sign/verify | controller **public** key | verify dispatches; **not** forge them |
| Worker→controller result/RPC | Ed25519 per-worker keypair | its **own private** key | sign only as itself; not impersonate another worker/actor |
| Per-job secrets | sealed to worker (see Decision 3) | its own private/session key | open only the envelopes dispatched to it while running |

The controller remains the most-trusted component and the root of the PKI. NATS
in-flight stays "encrypted + signed" (the signatures just become asymmetric).

## Decisions

### D1 — Ed25519 for `JobRequest` / `PipelineJobRequest` (controller→worker)

The controller signs each dispatch with its Ed25519 private key; workers verify
with the controller's public key (distributed as a non-secret config value, or
fetched from a controller endpoint at boot and pinned).

- **Alternative — keep HMAC but separate the request key:** rejected. Any
  symmetric key the worker can verify with, it can forge with; separation does
  not help.
- **Alternative — mTLS at the NATS layer:** complementary, not a substitute.
  mTLS authenticates the *connection*, not the *message*, and does not survive a
  message being relayed/stored; the per-message signature is the durable anchor
  (same reasoning that made the current HMAC per-message rather than per-conn).
- **Why Ed25519:** small keys/signatures (32/64 B), fast verify, no parameter
  choices to get wrong, already in the dependency tree via the Sigstore path.

### D2 — Per-worker Ed25519 keypairs for `JobResult` / RPC (worker→controller)

Each worker generates (or is provisioned) an Ed25519 keypair at boot and
registers its public key with the controller (see Migration P2). The worker signs
`JobResult`, `PipelineJobResult`, and the four RPC protocols with its private
key; the controller verifies against the registered public key keyed by the
signed, non-guest-controllable `worker_id` / `actor_id`.

- The landed `derive_worker_signing_key` HKDF primitive is repurposed here as an
  **optional deterministic keypair-derivation** path (derive an Ed25519 seed from
  a provisioning root + `worker_id`) for operators who prefer derived-not-stored
  worker identities. Registration (D2) still publishes only the *public* half.
- **Alternative — keep per-worker HMAC:** rejected (theater, per Context).

### D3 — Secret-envelope sealing (the hard part)

The worker must open per-job secrets without a fleet-wide decryption key. Two
viable shapes; **pick one in the Open Questions before P3**:

- **D3a — Seal to the dequeuing worker's X25519 public key (ECIES).** The
  controller encrypts each job's envelope to the *specific* worker that will run
  it. Requires **directed dispatch** (publish to a per-worker subject) instead of
  a NATS queue group, trading away automatic load-balancing for per-job
  confidentiality. Fits a scheduler that picks the worker.
- **D3b — Per-execution ephemeral sealing.** The worker sends an ephemeral X25519
  public key as part of claiming a job (a signed "claim" message under D2); the
  controller seals the envelope to that ephemeral key in the reply. Preserves
  queue-group load-balancing (any worker can claim) at the cost of an extra
  round-trip per job and a claim/lease protocol.

- **Alternative — keep the symmetric envelope but bound its exposure:** partial
  credit. Even sealing only *reduces* exposure to in-flight jobs; the current
  per-job AAD-derived envelope key (`envelope-aead/v2-per-job`) already limits a
  *leaked ciphertext* to one job, but not a *leaked root* — D3 is what closes the
  root exposure.

### D4 — Wire-format versioning + verify-once discipline

Add an explicit `crypto_scheme` version to each signed message (appended at the
end, per the wire-format-stability rule) so a mixed fleet can verify both HMAC
(legacy) and Ed25519 (new) during rollout. The `verify()` / `verify_no_replay()`
split and the r300/r301 verify-once rule carry over unchanged — the signature
primitive changes, the replay-cache discipline does not. The distributed
replay-nonce guard (finding #2, shipped) is orthogonal and keeps working.

## Migration plan

Each phase is independently shippable and default-off until the next is ready.
Workers roll **before/with** controllers at each format bump (the existing
envelope deploy-ordering rule).

- **P1 — Controller signing keypair + dual-verify workers.** Controller gains an
  Ed25519 keypair; publishes its public key. Workers verify `JobRequest` under
  Ed25519 **or** legacy HMAC (`crypto_scheme` dispatch), gated by
  `TALOS_DISPATCH_SCHEME`. Rollback: flip the flag back to HMAC-only.
- **P2 — Worker keypair registration.** A `POST /internal/worker-key`
  (mTLS-authed, NetworkPolicy-restricted, in-cluster only) or an operator-run
  registration CLI records worker public keys in a `worker_identities` table.
  Controller verifies `JobResult`/RPC under Ed25519-or-HMAC. Workers stop
  mounting `WORKER_SHARED_KEY` for *signing*.
- **P3 — Envelope sealing (D3a or D3b).** Land the chosen sealing scheme behind
  `TALOS_ENVELOPE_SEALING`. This is the phase that removes the last
  root-equivalent decryption key from the worker.
- **P4 — Enforcement flip.** Once all workers run Ed25519 + sealed envelopes, set
  `TALOS_DISPATCH_SCHEME=ed25519-only` / refuse legacy HMAC and stop distributing
  `WORKER_SHARED_KEY` to workers entirely. Loud SIEM log on any legacy-scheme
  message during the window (mirror the env-KEK / RLS guard style).

## Non-goals

- **Replacing the controller↔Vault / KEK trust** — the controller is still the
  PKI root and still owns the master key. This RFC only reshapes worker↔controller.
- **Confidential computing / attestation** (SEV-SNP, TDX). A stronger boundary,
  but orthogonal and far heavier; out of scope.
- **Changing the WASM sandbox itself.** The sandbox (fuel/epoch/memory limits,
  proposal lockdown, per-tier linkers) remains the first-line defense that makes
  native-code escape hard; this RFC bounds the blast radius *if* it is escaped.
- **Finding #2 (replay)** — already shipped (`talos-replay-guard`); unaffected.

## Open questions

1. **D3a vs D3b** — directed dispatch (lose queue-group LB) vs. claim-protocol
   (extra round-trip). Depends on how much the scheduler already knows the target
   worker. **Blocks P3.**
2. **Worker key lifecycle** — generated-and-registered per pod (ephemeral,
   re-register on restart) vs. derived-from-provisioning-root (stable, no
   registration write). Affects P2's registration surface.
3. **Controller-key rotation** — how workers learn a rotated controller public
   key without a restart (a signed key-set endpoint with an overlap window,
   mirroring `WORKER_SHARED_KEY_PREVIOUS`).
4. **Performance** — Ed25519 verify is ~µs but per-message; measure against the
   RPC hot path before P2 enforcement. HMAC is faster; confirm the delta is
   negligible at target RPS.

## Success criteria

- A worker process holds **no** symmetric key capable of forging a `JobRequest`
  or decrypting another job's secret envelope (verified by inspection +
  a red-team test that extracts all worker-resident key material and shows it
  cannot mint a valid dispatch nor open a sibling job's envelope).
- `JobResult`/RPC forged with a worker's key validate **only** for that worker's
  `worker_id` (existing per-identity binding, now cryptographic not just
  payload-bound).
- Mixed-fleet rollout completes with zero job failures (the `crypto_scheme`
  dual-verify path), and `TALOS_DISPATCH_SCHEME=ed25519-only` boots refuse the
  last legacy sender.
- `WORKER_SHARED_KEY` is no longer distributed to workers after P4.
