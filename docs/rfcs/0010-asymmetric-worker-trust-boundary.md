# RFC 0010 — Asymmetric worker-trust boundary

**Status:** In progress — P1 + P2 (inc.1–4) landed; P3 (D3b) fully wired &
compile-verified behind default-off `TALOS_ENVELOPE_SEALING` (crypto + claim
service + responder + engine/dispatcher/worker dispatch-loop wiring); remaining:
the live-NATS end-to-end run + canary before production enablement (see the
P3-status note below)
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
> off → HMAC unchanged.** **P1 sign coverage is COMPLETE:** every controller sign
> site routes through the one `configured_dispatch_signer()` source of truth — the
> engine dispatcher (primary + retry re-sign) and the module-push paths
> (`talos-webhooks`, `talos-gmail`, `talos-google-calendar`) — so the P4
> enforcement flip is unblocked once P2/P3 land.
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

### D3 — Secret-envelope sealing (the hard part) — **CHOSEN: D3b**

The worker must open per-job secrets without a fleet-wide decryption key. Two
shapes were considered; **D3b is chosen** (decision recorded 2026-07-04; see the
full protocol in [P3 detailed design](#p3-detailed-design--d3b-claimlease-envelope-sealing)):

- **D3a — Seal to the dequeuing worker's *static* X25519 public key (ECIES).** The
  controller encrypts each job's envelope to the *specific* worker that will run
  it. Requires **directed dispatch** (publish to a per-worker subject) instead of
  a NATS queue group, trading away automatic load-balancing. **Rejected on two
  counts:** (1) *security* — sealing to a long-lived recipient key has **no
  forward secrecy**; a sandbox escape that recovers the static X25519 private key
  decrypts *every envelope ever sealed to that worker*, including ciphertexts an
  attacker captured off the bus earlier. (2) *architecture* — today's dispatch is
  a **NATS queue group** (`{prefix}.jobs.{uid}`, the controller does not pick the
  worker); D3a forces the controller to become a scheduler and loses free
  load-balancing + failover (a job stranded on a worker that dies between publish
  and dequeue).
- **D3b — Per-execution ephemeral sealing (CHOSEN).** The worker generates a fresh
  ephemeral X25519 keypair per execution and sends the public half in a "claim"
  message signed with its long-term D2 worker identity; the controller verifies
  the claim, then seals the envelope to that ephemeral key. **Forward secrecy**
  (ephemeral–ephemeral ECDH) bounds a key compromise to the *single execution*
  whose ephemeral secret leaks — exactly the RFC's stated goal. **Preserves the
  queue-group model** unchanged (any worker claims). Cost: one added control-plane
  round-trip per job and a claim/lease state machine — both analysed and bounded
  in the detailed design below.

- **Alternative — keep the symmetric envelope but bound its exposure:** partial
  credit, and the **legitimate fallback if P3 is deferred.** Even sealing only
  *reduces* exposure to in-flight jobs; the current per-job AAD-derived envelope
  key (`envelope-aead/v2-per-job`) already limits a *leaked ciphertext* to one
  job, but not a *leaked root* — D3b is what closes the root exposure.

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

  > **P2 increment 1 landed (protocol foundation).** `crypto_scheme` +
  > `sign_ed25519_with_worker_id` / `verify_ed25519` / `verify_dispatch` on
  > `JobResult` and `PipelineJobResult` (`talos-workflow-job-protocol`, 6 unit
  > tests: roundtrip, non-empty-worker-id requirement, wrong-worker-key,
  > tamper, dispatch routing + P4 enforcement, downgrade-flip). Mirrors the P1
  > `JobRequest` machinery exactly; scheme-0 HMAC bytes unchanged.
  >
  > **P2 increment 2 landed (result-path wiring, end-to-end).** The worker
  > signs every `JobResult` / `PipelineJobResult` with a per-instance Ed25519
  > key when `TALOS_WORKER_SIGNING_KEY` (32-byte hex seed) is provisioned,
  > else keeps the legacy HMAC path — resolved once via
  > `worker::worker_result_signing_key()` and centralised in the
  > `sign_job_result` / `sign_pipeline_result` helpers so all four worker sign
  > sites (happy path + oversized-replacement, single + pipeline) share one
  > scheme decision. The controller resolves a worker's public key(s) by
  > `worker_id` from `TALOS_WORKER_PUBLIC_KEYS` (`worker_id=hex32` pairs,
  > repeat-id for rotation) via `job_protocol::worker_public_keys`, and every
  > result-verify site now routes on `crypto_scheme`:
  > `JobResult::verify_dispatch` (Primary — engine dispatcher, pipeline
  > dispatcher, webhook reply inbox) and `verify_no_replay_dispatch` (Observer
  > — the `talos.results.*` audit subscriber), both honouring
  > `job_protocol::result_accept_legacy_hmac()` (default accept;
  > `TALOS_RESULT_REQUIRE_ED25519` flips to refuse for P4). 3 new parser unit
  > tests (registry parse + verify, skip-malformed, empty-input). Default env
  > = unchanged HMAC behaviour; a compromised worker can forge results as
  > *itself* but never as another worker, and never a dispatch.
  >
  > **P2 increment 3 landed (RPC-path Ed25519, all five signed protocols).**
  > `talos-memory`'s `rpc_auth` gained the per-worker Ed25519 surface —
  > `RPC_CRYPTO_SCHEME_*` + a domain-separated, `worker_id`-bound signing input,
  > `register_ed25519_signing_key(worker_id, key)` (worker-only), `sign_rpc`
  > (the single scheme-decision point returning `(signature, worker_id,
  > crypto_scheme)`) and `verify_rpc` (routes on `crypto_scheme`; Ed25519 via
  > `job_protocol::worker_public_keys`, else HMAC gated by
  > `rpc_accept_legacy_hmac()` / `TALOS_RPC_REQUIRE_ED25519`). All five request
  > types (`memory_rpc`, `graph_rpc`, `database_rpc`, `state_rpc`,
  > `integration_state_rpc`) carry `#[serde(default)] worker_id + crypto_scheme`
  > (absent ⇒ scheme-0, so wire bytes stay byte-identical) and route their
  > `new_signed`/`verify` through the shared helpers. The worker registers its
  > result-signing key (`TALOS_WORKER_SIGNING_KEY`) as the RPC identity too, so
  > one keypair covers dispatch-reply AND all RPC. Freshness + the two-generation
  > nonce replay cache are untouched — the subscriber still calls
  > `check_and_record_nonce` separately, identically across schemes. 8 unit tests
  > (roundtrip, wrong-worker-key, tampered worker_id/subject/actor/nonce/body,
  > rotation overlap, empty-id/keyset + malformed-sig fail-closed, HMAC-vs-Ed25519
  > input domain separation). Landed in two commits: 3a (rpc_auth primitives),
  > 3b (thread through the five types + worker registration).
  >
  > **P2 increment 4 landed (dynamic registration).** `worker_identities` table
  > (migration `20260704120000`) + `talos-worker-identity-repository`
  > (advisory-lock-gated idempotent upsert with a per-worker active-key cap,
  > fail-loud `[u8;32]` decode, soft-retire, `supports_sealing` bit for P3/D3b),
  > verified against real Postgres. job_protocol's verifying-key registry became
  > an `ArcSwap` snapshot (lock-free reads; env base + controller-installable
  > dynamic overlay via `set_dynamic_worker_public_keys`, union + dedup +
  > full-replacement) so the DB registry merges in without touching the five
  > `worker_public_keys()` verify call sites. A controller refresh task
  > (`TALOS_WORKER_KEY_REFRESH_SECS`, default 60) re-publishes the active set;
  > eager-refresh after each registration write. Two paths write the table: the
  > operator CLI (`register/list/deactivate-worker-identity`, DB-credentialed,
  > verified end-to-end) and the in-cluster `POST /internal/worker-key` endpoint
  > for autoscaling self-registration — mounted only when
  > `TALOS_WORKER_REGISTRATION_TOKEN` is set, gated by a constant-time bearer
  > token + an Ed25519 proof-of-possession (`verify_strict`) over a canonical
  > domain-separated message + a freshness window, `no-nginx-route`, and an
  > opt-in `networkPolicy.workerRegistrationIngress` (default off). **Residual:**
  > the shared token authenticates "a legit worker pod", not a specific
  > `worker_id`, so a compromised token-holder could register its own key under
  > another `worker_id` — strictly smaller than the WSK model (any compromised
  > worker forges as ANY worker), with per-worker tokens / mTLS-SAN binding as
  > the hardening path. *(Closed 2026-07-05 — see "P2 hardening landed" below:
  > TOFU rule + single-use worker_id-bound provisioning tokens.)* **inc.4d landed (worker client):**
  > `worker::self_register` POSTs a PoP-signed registration at boot (detached,
  > best-effort, exponential-backoff retries, bails on non-429 4xx, no-op when
  > `TALOS_CONTROLLER_URL` / `TALOS_WORKER_REGISTRATION_TOKEN` are unset). A unit
  > test proves the worker-built body's proof verifies under the controller's
  > `verify_worker_registration_proof` — the cross-process contract. **P2 is now
  > complete** (inc.1–4); the boundary is Ed25519 end-to-end in both directions
  > with both static (env/CLI) and dynamic (self-registration) key distribution.
  >
  > **P2 hardening landed (2026-07-05) — registration bound to worker_id.**
  > Closes the shared-token impersonation residual above in three increments:
  > 1. **TOFU rule** (`WorkerIdentityRepository::register_tofu`, the only path
  >    the network endpoint now calls): a `worker_id`'s FIRST registered key
  >    becomes its trusted identity; afterwards the shared-token path accepts
  >    only an idempotent refresh of that exact ACTIVE key (bumps
  >    `last_seen_at`/`supports_sealing`). A different key, a re-activation of
  >    a deliberately deactivated key, or a new key for a fully-retired
  >    `worker_id` all 409 with a loud `talos_security`
  >    `worker_key_tofu_conflict` event. Deliberately stricter than
  >    "refuse only while an active key exists": workers never generate signing
  >    keys in-pod, so a legitimate new key always accompanies an operator, and
  >    rotation/revocation-reversal go through the DB-credentialed
  >    `register-worker-identity` CLI (unchanged `register()` semantics) or a
  >    bound provisioning token.
  > 2. **Single-use provisioning tokens** (`worker_provisioning_tokens`,
  >    migration `20260705130000`): operator-minted, expiring, stored as
  >    SHA-256 only (raw shown once at mint, never stored — the approval-gate
  >    token_hash discipline), optionally BOUND to one `worker_id`. Any bearer
  >    that is not the shared token takes this path (constant-time shared
  >    compare; shape + proof-of-possession validated BEFORE any consumption so
  >    garbage can't burn a token). Redemption is atomic inside the
  >    registration transaction — `UPDATE … WHERE used_at IS NULL … RETURNING`
  >    makes concurrent redeems admit exactly one, and a REFUSED registration
  >    rolls the consumption back. Semantics by binding: BOUND token =
  >    operator-grade `register()` (the mint was the explicit operator action —
  >    this is also the sanctioned rotation path for autoscaled fleets);
  >    WILDCARD token (`worker_id IS NULL`, migration compat) = TOFU semantics.
  >    `TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN=1` is the migration end-state:
  >    shared token and wildcard tokens are refused (inside the consume SQL, so
  >    nothing is burned), making every registration an explicit per-worker
  >    operator grant — the accept-legacy-then-require rollout shape P1/P2
  >    signing used. The endpoint also mounts in bound-token-only deployments
  >    (flag set, no shared token).
  > 3. **Ops surface**: `mint-worker-provisioning-token` (bound or explicit
  >    `--wildcard`, TTL-clamped, prints the raw token once), `list-` (metadata
  >    only, never the hash) and `revoke-worker-provisioning-token` (un-redeemed
  >    only) CLI subcommands; mints/revokes append to `admin_event_log`
  >    (`resource_type='worker_provisioning_token'`, `user_id` NULL on the CLI
  >    path). **Remaining residual:** while enforcement is OFF, a shared-token
  >    or wildcard holder can still claim a never-before-seen `worker_id`
  >    first-come-first-served; flip `TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN=1`
  >    to close it. mTLS client-certs with a worker_id-bound SAN remain the
  >    long-term alternative if the platform later wants to drop bearer
  >    credentials entirely.
- **P3 — Envelope sealing (D3b, chosen).** Land the claim/lease ephemeral-sealing
  scheme behind `TALOS_ENVELOPE_SEALING`. This is the phase that removes the last
  root-equivalent *secret-decryption* key from the worker. **Full protocol spec:**
  [P3 detailed design](#p3-detailed-design--d3b-claimlease-envelope-sealing) below.
  Gradual per-worker rollout depends on the P2 inc.4 `worker_identities`
  capability bit; an all-at-once fleet flip does not (see the rollout subsection).
  >
  > **P3 status (2026-07-04) — building blocks landed + tested, dispatch-loop
  > wiring is the remaining increment.** Everything that can be built and tested
  > without a live controller+worker+NATS+Redis cluster is done and green:
  > - **Crypto core** (`talos-workflow-job-protocol::envelope_seal`): `seal_secrets`
  >   / `WorkerEphemeral::open` (ephemeral-ephemeral X25519 → HKDF-SHA256(salt=
  >   exec_id) → AES-256-GCM, AAD = `exec_id||lp(worker_id)||epk_w`, non-contributory
  >   rejection, zeroize), and the `SecretClaim` / `SealedSecrets` / `ClaimResponse`
  >   signed wire types. 12 unit tests.
  > - **Wire fields**: `JobRequest`/`PipelineJobRequest` gained `sealing` +
  >   `secret_paths`; `JobRequest` gained `claim_inbox`. All bound into
  >   `signing_payload` only when `sealing != 0` and `skip_serializing_if`-omitted
  >   when default, so a legacy message is **byte-identical** on the wire AND in
  >   the signing payload (proven by the unchanged wire snapshots).
  > - **Controller claim service** (new crate `talos-envelope-seal`):
  >   `EnvelopeSealingMode` (off/audit/required), `InFlightSeals` (atomic-`take`
  >   single-claim), `handle_secret_claim` (authenticate via the P2 registry →
  >   take → seal), `RedisLease` (Lua-CAS durability), and `run_claim_responder`
  >   (the single primary `verify()` caller, per the r300/r301 rule). 7 unit tests
  >   + a live-Redis lease CAS test (validated).
  > - **Worker claim client** (`worker::secret_claim`): `build_claim` /
  >   `process_reply` (fail-closed, forward-secret) + the `claim_secrets` NATS
  >   wrapper. 3 unit tests (roundtrip vs a simulated controller, rejection,
  >   wrong-controller-key).
  > - **Live-NATS integration test** (`talos-envelope-seal/tests/`, gated on
  >   `TALOS_TEST_NATS_URL`): responder↔worker-client handshake, single-claim,
  >   unknown-execution. Compiles; runs in `quality.yml`'s env-gated suite (no
  >   broker in the dev sandbox).
  >
  > **Dispatch/receive-loop wiring — LANDED (compile-verified; end-to-end run
  > gated on the live-NATS integration test).** All behind default-off
  > `TALOS_ENVELOPE_SEALING`; unset ⇒ byte-identical to today.
  > 1. `DispatchJob` (`talos-workflow-engine-core`) gained `plaintext_secrets`
  >    (redacted `Debug`) + `secret_paths`. When claim-based sealing is on the
  >    engine (`engine_dispatch_single`) calls `resolve_secrets_map_for` and puts
  >    the plaintext there instead of sealing (step 6 skipped).
  > 2. `NatsNodeDispatcher` gained `with_envelope_sealing(EnvelopeSealingHandle
  >    { Arc<InFlightSeals>, claim_subject })`. When a job carries
  >    `plaintext_secrets`: register `InFlightSeals[job_id]`, stamp `req.sealing=1`
  >    / `claim_inbox` / `secret_paths` BEFORE signing; empty `encrypted_secrets`.
  >    Fail-closed if plaintext arrives without a handle (never plaintext on the
  >    wire). Discards the context after dispatch (bounds the map on pre-claim
  >    failure).
  > 3. `talos-engine::build_nats_dispatcher` (the single dispatcher construction
  >    point the controller already calls — so **no controller `main.rs` change**)
  >    lazily creates a process-wide `InFlightSeals` + claim subject
  >    (`client.new_inbox()`) and spawns `run_claim_responder` once (memoized in a
  >    `OnceLock`), then injects the handle. Requires the controller Ed25519
  >    signing key (P3 builds on P1); if sealing is on without it, it logs and
  >    attaches no handle so claim dispatches fail closed loudly.
  > 4. Worker `execute_job` threads the NATS client in; `req.sealing==1` →
  >    `secret_claim::claim_secrets` instead of decrypting; downgrade guard
  >    (`worker_sealing_required()`) refuses `sealing==0` under `required`.
  > 5. Fleet-wide, not per-worker: under queue-group dispatch the controller can't
  >    pick the worker, so `audit`/`required` seals **every** single-node dispatch
  >    and every worker must understand claims first (the RFC's all-at-once flip).
  >    The `supports_sealing` capability bit is informational here, not a
  >    per-dispatch gate.
  >
  > **`required`-mode coverage (2026-07-04).** ALL workflow shapes now seal under
  > the flag — single-node, **loop-body**, AND **pipeline** dispatches:
  > - Single-node + loop-body share the `build_dispatch_secrets_for` decision helper
  >   (a loop body is no longer left inline).
  > - **Pipelines** seal per step in ONE claim: the engine resolves each step's
  >   plaintext, the dispatcher (`dispatch_chain`) collects them into a per-step
  >   `Vec<HashMap<String,String>>` sealed as a single `InFlightSeals` entry keyed on
  >   the pipeline `job_id` (`SealContext::from_bytes`), stamps `PipelineJobRequest`
  >   `sealing=1`/`claim_inbox`/`secret_paths`, and clears every step's inline
  >   envelope. The worker (`execute_pipeline_job`) does ONE `claim_secrets_raw`,
  >   deserializes the per-step vector, and feeds step `i` its own map — so per-step
  >   isolation is preserved with a single round-trip.
  > - **Downgrade guard is precise**: the worker refuses a `sealing=0` dispatch under
  >   `required` ONLY when it carries a non-empty WSK envelope (a real decryption). A
  >   no-secret node/step (empty envelope) decrypts nothing and is allowed, so
  >   secretless transforms/routers don't break under `required`.
  >
  > `required` is now safe to enable for every workflow shape. Validated end-to-end
  > over live NATS: `full_claim_loop_over_live_nats` (single-node) and
  > `full_pipeline_claim_loop_over_live_nats` (2-step pipeline, per-step secrets), both
  > asserting no plaintext on the wire.
  >
  > **Remaining before production enablement:** run the live-NATS integration
  > test (+ a Redis lease) against a real cluster, then a canary with
  > `TALOS_ENVELOPE_SEALING=audit` before `required`. The dev sandbox has no
  > `nats-server`, so the end-to-end path is compile-verified + unit/component-
  > tested here, not yet run.
- **P4 — Enforcement flip.** Once all workers run Ed25519 + sealed envelopes, set
  `TALOS_DISPATCH_SCHEME=ed25519-only` / refuse legacy HMAC and stop distributing
  `WORKER_SHARED_KEY` to workers entirely. Loud SIEM log on any legacy-scheme
  message during the window (mirror the env-KEK / RLS guard style).

## P3 detailed design — D3b claim/lease envelope sealing

This section is the implementation spec for P3. It is deliberately concrete: the
envelope leg is the highest-blast-radius change in the RFC (it sits on the signed
data plane `CLAUDE.md` flags as total-outage-prone, r300/r301), so the message
shapes, state machine, and failure recovery are pinned down here before any code.

### What changes, and what does not

**Changes:** *only the secret-delivery leg.* Today the controller pre-seals the
job's secrets under a `WORKER_SHARED_KEY` (WSK) HKDF subkey and embeds the
`EncryptedSecrets { ciphertext, nonce }` inside the `JobRequest` at publish time;
the worker opens it with the same fleet-wide root. Under D3b the `JobRequest`
carries **no sealed secrets** — instead the worker claims the job with a fresh
ephemeral X25519 public key and the controller seals to *that* key.

**Unchanged:** the `JobResult` / `PipelineJobResult` signing path (P2 inc.1/2),
the five signed RPC protocols (P2 inc.3), dispatch signing (P1), the replay-nonce
guard (finding #2), the checkpoint AEAD (`checkpoint-aead/v2-per-execution`) and
OTLP-header folds — those are **separate WSK derivations** (per `CLAUDE.md`) that
P3 does **not** close and does **not** need to. P3's scope is precisely: *remove
WSK as a secret-decryption root on the worker.* After P3 + P4, WSK is no longer
distributed for signing (P2) or secret-sealing (P3); any residual WSK-derived
material (checkpoints) is tracked separately and called out as a known non-goal
here so nobody reads P4 as "WSK fully gone."

### Message flow

Four messages replace today's two. "RTT+1" = one added control-plane round-trip.

```
  Controller                         NATS                          Worker (queue group)
     │                                                                   │
  1. │ JobDispatch (no secrets,        ──▶  {prefix}.jobs.{uid}  ──▶      │  dequeue (LB picks one)
     │   secret_paths, exec_id,             (queue group)                │  verify controller Ed25519 sig
     │   reply=R1)  Ed25519-signed                                       │  gen ephemeral (esk_w, epk_w)
     │                                                                   │
  2. │            claim on R1  ◀──────────────────────────────────────  │  SecretClaim{exec_id, worker_id,
     │  verify worker Ed25519 sig (D2 registered key)                    │    epk_w, claim_nonce}
     │  CAS lease exec_id: dispatched → claimed_by(worker_id)            │    Ed25519-signed (long-term)
     │  seal secrets to epk_w (ephemeral-ephemeral ECDH)                 │
     │                                                                   │
  3. │  SealedSecrets{exec_id, epk_c,  ──▶  reply to claim (R2)  ──▶      │  verify controller sig
     │    ciphertext, nonce}                                             │  ECDH(esk_w, epk_c) → open
     │    Ed25519-signed                                                 │  run job; zeroize esk_w
     │                                                                   │
  4. │            JobResult  ◀─────────────────────────────────────────  │  (unchanged P2 path)
     │  verify_dispatch (Ed25519-or-HMAC)                                │  Ed25519-signed by worker
```

Messages 2 and 3 are the added round-trip. Message 1 is the existing dispatch
minus the inline envelope plus a `secret_paths` list and a `sealing` discriminant;
message 4 is the existing result, untouched.

### New wire types (append-only, `#[serde(default)]`)

Per the D4 wire-stability rule, every new field is appended and defaulted so a
scheme-0 (inline-WSK) message stays byte-identical.

- **`JobRequest` / `PipelineJobRequest` gain:**
  - `sealing: u8` (default `0`) — `0` = inline WSK envelope (legacy, today);
    `1` = claim-based ECIES (D3b). Bound into the dispatch signing payload (it is
    security-relevant: an attacker must not downgrade `1`→`0` to force the worker
    back onto a WSK envelope, so it is appended to the signed bytes exactly like
    `crypto_scheme` was).
  - `secret_paths: Vec<String>` (default empty) — the vault paths this job is
    permitted to resolve, sent in the clear (paths are not secrets; values are).
    Only populated when `sealing == 1`; the controller resolves + seals the
    *values* on claim. Reuses the existing per-module allowlist
    (`job_protocol::vault_path_permitted`) so the claim can't widen scope.
  - When `sealing == 1`, `encrypted_secrets` is `EncryptedSecrets::empty()`.
- **`SecretClaim` (new signed message, worker→controller):**
  `{ exec_id: Uuid, worker_id: String, epk_w: [u8;32], claim_nonce: String,
  issued_at_ms: u64, crypto_scheme: u8, signature: Vec<u8> }`. Signed with the
  worker's **long-term** D2 Ed25519 key (NOT the ephemeral key) — this is the
  binding that authenticates *who* is claiming; the ephemeral key only provides
  confidentiality. Verified via `job_protocol::worker_public_keys(worker_id)`,
  reusing the P2 registry verbatim. Carries a nonce + timestamp so the existing
  freshness window + replay-nonce guard apply unchanged.
- **`SealedSecrets` (new signed message, controller→worker):**
  `{ exec_id: Uuid, epk_c: [u8;32], ciphertext: Vec<u8>, nonce: [u8;12],
  issued_at_ms: u64, signature: Vec<u8> }`. Signed with the controller's P1
  Ed25519 key; the worker verifies with `TALOS_CONTROLLER_PUBLIC_KEY` (same key
  already pinned for dispatch). The `epk_c` is the controller's per-seal ephemeral
  X25519 public key.

### Cryptographic construction (the seal)

Ephemeral–ephemeral X25519 ECDH so **both** ends contribute forward secrecy;
worker identity is bound out-of-band by the Ed25519 claim signature (clean
separation: **Ed25519 authenticates *who*, X25519 provides *confidentiality +
FS***). No new primitive families — all four crates are already in-tree
(`ed25519-dalek`, `aes-gcm`, `hkdf`; add `x25519-dalek`, same dalek family).

```
worker:      (esk_w, epk_w) = X25519::generate()          # per execution, zeroized after open
controller:  (esk_c, epk_c) = X25519::generate()          # per seal
shared:      ss   = X25519(esk_c, epk_w)  ==  X25519(esk_w, epk_c)
             key  = HKDF-SHA256(ikm = ss,
                                salt = exec_id.as_bytes(),
                                info = b"talos/envelope-seal/v3-ecies")   # 32 bytes
             aad  = exec_id || worker_id || epk_w          # transposition-proof binding
             ct   = AES-256-GCM(key, nonce=random-96-bit, plaintext=secrets_json, aad)
```

`ss` MUST be rejected if it is the all-zero output (contributory-behaviour check —
`x25519-dalek` returns a zero shared secret for low-order points; fail closed).
The AAD binds the ciphertext to the exact `(execution, worker, ephemeral key)`, so
a `SealedSecrets` cannot be replayed against a different execution or a different
claim even by a party who captured it.

### Security properties (each tied to the threat)

1. **Ephemeral-key authenticity (the critical one).** `epk_w` is signed *inside*
   the `SecretClaim` by the worker's registered long-term Ed25519 key. The
   controller verifies that signature before sealing. Without this, a rogue
   worker or an on-bus attacker substitutes its own `epk_w` and the controller
   seals the secrets straight to the attacker. This is the property that makes
   the ephemeral-ephemeral construction safe.
2. **Forward secrecy (the reason D3b beats D3a).** `esk_w` and `esk_c` are
   per-execution/per-seal and zeroized after use. A later compromise of the
   worker's long-term Ed25519 key — or of the controller's — does **not** decrypt
   any captured past `SealedSecrets`; the ECDH secrets that opened them no longer
   exist. Blast radius of a sandbox escape = the secrets of the jobs whose
   ephemeral key is *currently resident*, i.e. in-flight on that worker.
3. **Single-claim / no double-run.** The controller CAS-es a per-`exec_id` lease
   (`dispatched → claimed_by`); a second claim (NATS redelivery, or a racing rogue
   worker) is rejected with `ClaimRejected`, and the loser aborts without secrets.
   Exactly one worker ever receives the sealed values.
4. **Freshness / anti-replay.** The claim's nonce + `issued_at_ms` ride the
   existing asymmetric freshness window and the distributed replay-nonce guard
   (finding #2) — no new replay surface.
5. **Downgrade resistance.** `sealing` is in the signed dispatch payload; an
   attacker cannot flip `1`→`0` to force a WSK envelope. Under
   `TALOS_ENVELOPE_SEALING=required` the worker refuses a `sealing==0` dispatch
   outright.
6. **Confidentiality vs. the transport.** NATS operators / bus sniffers see only
   ciphertext sealed to an ephemeral key they do not hold. (Complementary to, not
   dependent on, NATS mTLS.)

### Lease / single-claim state machine

State lives in **Redis** (already present for the replay guard), keyed
`seal:lease:{exec_id}`, value `{state, worker_id?, dispatched_at}`, `PX =
lease_ms` (default 30 s, ≥ the dispatch-to-claim budget). Because a NATS reply
inbox is connection-scoped, the claim (msg 2) returns to the **same controller
replica** that dispatched (msg 1); Redis is used not for cross-replica handoff but
for crash-recovery + the re-dispatch decision.

```
   (msg1 dispatch)      SET NX seal:lease:{exec_id} = {dispatched}  PX lease_ms
   (msg2 claim)         CAS {dispatched} → {claimed_by:wid}
                          ├─ success → seal + send SealedSecrets (msg3)
                          ├─ already {claimed_by:other} → ClaimRejected (loser aborts)
                          └─ key missing/expired → ClaimRejected (lease lost; job re-dispatched)
   (lease expiry)       no valid claim within lease_ms → re-dispatch OR fail execution
```

### Failure modes & recovery

| Event | Handling |
|---|---|
| Worker dequeues, dies before claim | Lease expires → controller re-dispatches (bounded retry) → different worker, new ephemeral. |
| Two workers dequeue (NATS redelivery) | Both claim; CAS admits one; loser gets `ClaimRejected` and drops the job **without** running (no secretless execution). |
| Controller replica dies between dispatch and claim | Claim's reply inbox is dead → worker's claim request times out → worker aborts → lease expires → surviving replica re-dispatches. |
| Worker claims, opens, then dies mid-run | Existing crash-recovery/`resuming` path (unchanged). Resume issues a **new** dispatch → new ephemeral → new seal; the dead ephemeral is irrelevant. |
| Oversized secrets | Unchanged semantics; only the `SealedSecrets` ciphertext is larger. |
| `sealing==0` under `required` | Worker refuses (downgrade guard). |

### Performance analysis

- **Latency:** +1 control-plane RTT per job (claim + sealed-secrets). In-cluster
  NATS request/reply is sub-ms p50 / low-single-digit-ms p99 — negligible against
  WASM execution (tens of ms to seconds). Confirm with the same bench harness
  Open-Question 4 mandates for P2.
- **CPU:** +2 X25519 scalar mults (one per side, ~tens of µs each) + 1 HKDF + the
  AES-GCM already performed today; +1 Ed25519 sign (worker claim) + 1 verify
  (controller). Sub-100 µs total added per job. Negligible.
- **Memory / state:** one short-lived, auto-expiring Redis key per in-flight job
  (`SET NX PX`). Bounded by concurrency, not by jobs-ever-seen — no monotonic
  growth (the cache-pattern rule).
- **Wire bytes:** dispatch **shrinks** (inline envelope removed); two small
  control messages added. Roughly net-neutral.

Net: the cost is dominated by one small, constant RTT — an acceptable price for
forward secrecy while keeping queue-group load-balancing.

### Rollout, flags, deploy ordering, rollback

- **Flag:** `TALOS_ENVELOPE_SEALING` ∈ `{off, audit, required}`, mirroring the
  Sigstore three-policy shape. `off` (default) = today's inline WSK envelope,
  byte-identical. `audit` = controller uses claim-based sealing for
  claim-capable workers, still accepts inline for others (migration window).
  `required` = refuse `sealing==0` (the P4-adjacent enforcement point for
  secrets).
- **Gradual (heterogeneous) rollout depends on P2 inc.4.** To seal claim-based to
  *some* workers and inline to others, the controller must know which workers
  speak the claim protocol — a `supports_sealing` capability bit in the
  `worker_identities` table (P2 inc.4). **This is where inc.4 becomes
  load-bearing**, and the reason inc.4 should land before a mixed-fleet P3.
- **All-at-once flip does NOT need inc.4.** With the static
  `TALOS_WORKER_PUBLIC_KEYS` registry, an operator upgrades every worker (claim
  protocol understood, still defaulting to inline), then flips
  `TALOS_ENVELOPE_SEALING=required` fleet-wide — same shape as the dispatch-scheme
  flip. Fine for single/few-worker (homelab) deploys.
- **Deploy ordering (existing rule):** workers roll **before/with** controllers.
  A claim-based controller talking to a pre-P3 worker that never sends a claim
  would strand the job; so upgrade workers first (they understand claims, default
  inline), then flip the controller. **Rollback:** set `TALOS_ENVELOPE_SEALING=off`
  — the controller reverts to inline WSK sealing with zero worker change.

### New dependencies

- `x25519-dalek` (ECDH) — same dalek family already pulled for Ed25519 via the
  Sigstore path; `zeroize` (already in-tree) for `esk_*`.

### Verify-once / D4 discipline

`SecretClaim` and `SealedSecrets` are new signed message types, so — per the
r300/r301 rule in `CLAUDE.md` — each ships with **both** `verify()` and
`verify_no_replay()` from the start, and each has **exactly one** primary
`verify()` caller per controller process (the claim handler for `SecretClaim`; the
worker for `SealedSecrets`). No passive observer double-verifies. The claim is
single-published to its reply inbox only.

### Test plan (gate on live NATS, not just `cargo test`)

- **Unit (pure):** ECDH seal/open roundtrip; wrong-`epk` fails; AAD transposition
  (swap `exec_id`/`worker_id`) fails; low-order-point/zero-`ss` rejected;
  `sealing` downgrade rejected under `required`; claim signature bound to
  long-term key (a claim signed by a different key fails); `SealedSecrets` AAD
  binding; append-only wire snapshots prove scheme-0 bytes unchanged.
- **State machine (Redis harness):** CAS single-claim (second claim rejected);
  lease-expiry re-dispatch; loser-aborts-without-secrets.
- **Integration (live NATS + Redis, in `quality.yml`'s env-gated suite):** full
  dispatch→claim→seal→open→result happy path; NATS-redelivery double-claim; worker
  death before/after claim; controller-replica death between dispatch and claim.
  This is the phase where unit tests are **not** sufficient — the claim/lease
  timing and reply-inbox routing only exercise against a real broker.

## Operator runbook (turning it on)

Keys are minted with the controller binary — the ONE supported generator (hand-
rolling with `openssl` produces a PKCS#8/PEM wrapper the loaders reject; they
want a raw 32-byte seed / point in hex):

```
# Controller dispatch keypair (P1: controller signs dispatches, workers verify)
controller generate-worker-trust-keypair --role controller

# Per-worker keypair (P2: worker signs results + RPC, controller verifies)
controller generate-worker-trust-keypair --role worker --worker-id <worker-id>
```

Each invocation prints a copy-pasteable env block labelled by which process gets
which half. The `SIGNING` values are secrets → put them in the pod's Secret, not
`values.yaml`. Rollout order (each step is safe to sit in for as long as needed —
every verify path dual-accepts HMAC while the scheme flags are unset/false):

1. **Dispatch (P1).** Set `TALOS_CONTROLLER_PUBLIC_KEY` on all workers first
   (they now *accept* Ed25519 but still accept HMAC), then flip
   `TALOS_DISPATCH_SCHEME=ed25519` + `TALOS_CONTROLLER_SIGNING_KEY` on the
   controller. Roll workers to enforce with `TALOS_DISPATCH_REQUIRE_ED25519=1`.
2. **Results + RPC (P2).** Register every worker's public key in the controller's
   `TALOS_WORKER_PUBLIC_KEYS` (comma-separated `worker_id=hex`) first, then set
   each worker's `TALOS_WORKER_SIGNING_KEY` (one key covers both result and RPC
   signing). Enforce later with `TALOS_RESULT_REQUIRE_ED25519=1` /
   `TALOS_RPC_REQUIRE_ED25519=1`.
3. **P4 flip** once every worker signs Ed25519: set the three `*_REQUIRE_ED25519`
   flags and stop distributing `WORKER_SHARED_KEY` for signing.

Rotation: publish the new public key alongside the old (workers accept a
comma-separated `TALOS_CONTROLLER_PUBLIC_KEY_PREVIOUS`; the controller accepts a
repeated `worker_id=` entry in `TALOS_WORKER_PUBLIC_KEYS`), roll the signer, then
drop the old key.

> **Not yet wired into the Helm chart.** The env vars above are read by the
> controller/worker binaries but the chart does not expose them yet (the signing
> keys need Secret plumbing, not `values.yaml`). Until then, set them via the
> deployment's existing Secret/env mechanism. Chart plumbing is tracked with the
> P2 inc.4 registration work.

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

1. ~~**D3a vs D3b** — directed dispatch (lose queue-group LB) vs. claim-protocol
   (extra round-trip).~~ **RESOLVED (2026-07-04): D3b.** Today's dispatch is a NATS
   queue group (the controller does not pick the worker), so D3a's directed
   dispatch would mean building a scheduler and losing free load-balancing +
   failover; and D3a's static-key seal has no forward secrecy. D3b keeps the queue
   group and gives per-execution forward secrecy for one added round-trip. Full
   protocol in [P3 detailed design](#p3-detailed-design--d3b-claimlease-envelope-sealing).
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
