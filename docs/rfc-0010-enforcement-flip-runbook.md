# RFC 0010 P4 — Production Enforcement Flip (WORKER_SHARED_KEY retirement)

**Goal:** retire the symmetric `WORKER_SHARED_KEY` as the fleet's crypto
root. Until the three gates below are flipped in production, a leaked
shared key lets a compromised worker forge RPC for any actor, impersonate
any other worker, and (pre-sealing) decrypt secret envelopes. The dev
stack has run the fully-enforced posture since 2026-07-06
(`TALOS_DISPATCH_SCHEME=ed25519` + `TALOS_ENVELOPE_SEALING=required`),
validated end-to-end over live NATS including the sealed-secret
round-trip. This runbook is the production sequence.

Related docs: `docs/rfcs/0010-asymmetric-worker-trust-boundary.md`
(design), `docs/worker-shared-key-rotation.md` (rotating the legacy key
while it still exists).

## Preconditions

1. **Controller signing key** — `TALOS_CONTROLLER_SIGNING_KEY` (Ed25519,
   generated via `controller keypair-gen`) present in the bootstrap
   Secret. Required for SealedSecrets signing; without it
   `TALOS_ENVELOPE_SEALING=required` fails every secret-carrying dispatch.
2. **Worker fleet identity** — every worker's Ed25519 public key listed
   in `TALOS_WORKER_PUBLIC_KEYS` on the controller (static fleet identity;
   see the chart's `controller.env` block). A worker whose key is missing
   has its results REJECTED once result enforcement flips.
3. **Images** — controllers and workers on builds ≥ the P3 wiring
   (2026-07-06 canary or later). Envelope deploy-ordering rule applies:
   workers roll first/together with controllers.
4. **Rollback plan** — each phase below is a single env-var change;
   rollback = revert the var and `helm upgrade` (secret-rotation
   auto-bounce rolls the pods).

## Sequence (one phase per deploy window; verify between each)

Run each phase for at least one full day of scheduled-workflow traffic
before the next.

### Phase A — dispatch signing to Ed25519
- Set `TALOS_DISPATCH_SCHEME=ed25519` (controller).
- Effect: JobRequest/PipelineJobRequest signed with the controller key;
  workers verify either scheme, so this is forward-compatible.
- Verify: `tail_worker_logs` shows zero signature-verification failures;
  `get_health_dashboard` failure counts flat vs baseline.

### Phase B — envelope sealing to `required`
- Set `TALOS_ENVELOPE_SEALING=audit` for one window, then `required`.
- Effect at `required`: workers refuse non-sealed secret-carrying
  dispatches; plaintext secrets never ride the WSK envelope. No-secret
  nodes still run (the downgrade guard is precise).
- Verify in `audit`: `talos_rpc`/audit logs show claim round-trips on
  every secret-carrying job, zero claim failures. Verify in `required`:
  scheduled workflows with vault-backed headers (Gmail fetchers) still
  succeed end-to-end.

### Phase C — result verification to Ed25519-only
- Set `TALOS_RESULT_REQUIRE_ED25519=1` (controller). This flips
  `result_accept_legacy_hmac()` off — an HMAC-signed JobResult is now
  rejected, so EVERY worker must be on its Ed25519 identity first
  (precondition 2).
- Verify: no `"Job result signature verification failed"` in controller
  logs; per-worker attribution (`talos_job_audit` target) shows non-empty
  `worker_id` on all results.

### Phase D — RPC plane to Ed25519-only
- Set `TALOS_RPC_REQUIRE_ED25519=1` (controller). Signed NATS-RPC
  (memory/graph/database/state/ml) from workers must carry Ed25519.
- Verify: `talos_rpc` metrics show zero `unauthorized` spikes on
  `talos.memory.op` / `talos.graph.search` after the flip.

### Phase E — retire the key
- Once A–D have soaked: rotate `WORKER_SHARED_KEY` one final time (it
  still keys the legacy checkpoint/envelope HKDF derivations —
  `checkpoint-aead/v2-per-execution`, `envelope-aead/v2-per-job` — so it
  cannot be REMOVED yet; retirement here means it is no longer a
  signing/trust root, only a local KDF input).
- File the follow-up to migrate checkpoint/envelope KDFs off the WSK
  before full deletion.

## Failure signatures

| Symptom after a flip | Cause | Action |
|---|---|---|
| every job fails signature-verify | worker image predates P2 or key missing from `TALOS_WORKER_PUBLIC_KEYS` | revert phase, fix fleet identity |
| secret-carrying jobs fail, no-secret jobs fine | Phase B with missing `TALOS_CONTROLLER_SIGNING_KEY` or worker predates P3 | revert to `audit`, check precondition 1 |
| `result_nonce already seen` storms | dual-verify regression, NOT the flip — see the verify-once rule in CLAUDE.md | do not revert; fix the second verifier |
